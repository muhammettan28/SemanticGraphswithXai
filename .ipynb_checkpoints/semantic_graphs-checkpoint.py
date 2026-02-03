# -*- coding: utf-8 -*-
"""
Semantic Graph Analyzer (graph vs manifest ayrımlı, FPR azaltmalı, squash'lı)
Toplam ≈ squash( SemGraph + β·SemManifest ) + 0.6·Yapısal + Yumuşak Bonuslar
"""

from pathlib import Path
import math
import json
import networkx as nx
from androguard.misc import AnalyzeAPK

# -------------------- Sabitler --------------------

STOP_CLASSES = frozenset([
    'Ljava/lang/Object;', 'Ljava/lang/String;', 'Ljava/lang/StringBuilder;',
    'Ljava/lang/Integer;', 'Ljava/lang/Long;', 'Ljava/lang/Boolean;',
    'Ljava/lang/Class;', 'Ljava/lang/Thread;', 'Ljava/lang/Exception;'
])

DANGEROUS_PERMISSIONS = frozenset({
    "READ_SMS","SEND_SMS","RECEIVE_SMS","READ_PHONE_STATE","CALL_PHONE",
    "READ_CALL_LOG","WRITE_CALL_LOG","ACCESS_FINE_LOCATION","ACCESS_COARSE_LOCATION",
    "CAMERA","RECORD_AUDIO","READ_CONTACTS","WRITE_CONTACTS","READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE","SYSTEM_ALERT_WINDOW","WRITE_SETTINGS","DEVICE_ADMIN"
})

CATEGORY_RULES = {
    "network": ["Landroid/net","Ljava/net","HttpURLConnection","URLConnection",
                "OkHttp","okhttp3","Volley","Socket","ServerSocket"],
    "telephony": ["Landroid/telephony","Telephony","TelephonyManager"],
    "sms": ["Sms","TextMessage","SmsManager","sendTextMessage",
            "sendMultipartTextMessage","android.provider.Telephony"],
    "crypto": ["Ljavax/crypto","Ljava/security","Cipher","MessageDigest",
               "KeyGenerator","SecretKey","encrypt","decrypt","AES","RSA"],
    "reflection": ["Ljava/lang/reflect","Class;->forName","getDeclaredMethod"],
    "dynamic": ["DexClassLoader","PathClassLoader","System.loadLibrary",
                "System.load","dalvik.system.DexFile","InMemoryDexClassLoader"],
    "dangerous_permissions": ["DEVICE_ADMIN","SYSTEM_ALERT_WINDOW","WRITE_SETTINGS"],
    "file_operations": ["java.io.File","FileInputStream","FileOutputStream",
                        "RandomAccessFile","/system/","/data/data/","getExternalStorageDirectory",
                        "openFileOutput","openFileInput","deleteFile"],
    "device_info": ["getDeviceId","getSubscriberId","getSimSerialNumber","getLine1Number",
                    "Build.SERIAL","Settings.Secure.ANDROID_ID","WifiInfo.getMacAddress",
                    "BluetoothAdapter.getAddress","getInstalledPackages","getRunningTasks"],
    "location": ["LocationManager","GPS_PROVIDER","NETWORK_PROVIDER",
                 "getLastKnownLocation","requestLocationUpdates","getCellLocation"],
    "media_capture": ["Camera","MediaRecorder","AudioRecord","takePicture",
                      "startRecording","setAudioSource","setVideoSource"],
    "root_detection": ["/system/bin/su","/system/xbin/su","Superuser.apk","SuperSU",
                       "busybox","which su","Runtime.exec","ProcessBuilder"],
    "admin_operations": ["DevicePolicyManager","DeviceAdminReceiver","lockNow",
                         "wipeData","resetPassword","setPasswordQuality","ComponentName"],
    "obfuscation": ["String.charAt","StringBuilder.reverse","Base64.decode",
                    "Base64.encode","URLDecoder.decode","URLEncoder.encode",
                    "xor","\\x","unicode","StringBuffer"],
    "background_ops": ["startService","bindService","ServiceConnection","BroadcastReceiver",
                       "sendBroadcast","registerReceiver","AlarmManager","PendingIntent"],
    "banking_targets": ["com.android.vending","market://","play.google.com",
                        "banking","wallet","payment","paypal","bank"],
    "native_code": ["System.loadLibrary","native","JNI","NDK",".so","arm64","x86","mips"],
    "anti_debug": ["Debug.isDebuggerConnected","ActivityManager.isUserAMonkey",
                   "Build.TAGS","test-keys","ApplicationInfo.FLAG_DEBUGGABLE",
                   "/proc/self/status","TracerPid"],
    "modern_libs": ["androidx.","com.google.firebase","org.json","kotlin.coroutines"],
    "privileged_ops": []  # sadece manifest
}

PERM_TO_CATEGORY = {
    "READ_SMS":"sms","RECEIVE_SMS":"sms","SEND_SMS":"sms","RECEIVE_WAP_PUSH":"sms",
    "READ_PHONE_STATE":"device_info","GET_ACCOUNTS":"device_info","GET_TASKS":"device_info",
    "READ_CONTACTS":"device_info","WRITE_CONTACTS":"device_info",
    "CAMERA":"media_capture","RECORD_AUDIO":"media_capture",
    "ACCESS_FINE_LOCATION":"location","ACCESS_COARSE_LOCATION":"location",
    "READ_EXTERNAL_STORAGE":"file_operations","WRITE_EXTERNAL_STORAGE":"file_operations",
    "SYSTEM_ALERT_WINDOW":"admin_operations","WRITE_SETTINGS":"admin_operations",
    "DEVICE_ADMIN":"admin_operations",
    "RECEIVE_BOOT_COMPLETED":"background_ops","WAKE_LOCK":"background_ops",
    "INSTALL_PACKAGES":"privileged_ops","RESTART_PACKAGES":"privileged_ops",
    "READ_LOGS":"privileged_ops","STATUS_BAR":"privileged_ops",
    "EXPAND_STATUS_BAR":"privileged_ops","READ_FRAME_BUFFER":"privileged_ops",
    "com.google.android.c2dm.permission.RECEIVE":"background_ops",
}

BENIGN_HINT_PERMS = frozenset({
    "USE_FINGERPRINT","NFC","NFC_TRANSACTION","SMARTCARD",
    "org.simalliance.openmobileapi.SMARTCARD",
    "AUTHENTICATE_ACCOUNTS","MANAGE_ACCOUNTS",
    "com.google.android.providers.gsf.permission.READ_GSERVICES",
    "BLUETOOTH","BLUETOOTH_ADMIN",
    "com.google.android.c2dm.permission.RECEIVE"  # FCM
})

# Davranış ağırlıkları
W = {
    "sms": 15.5, "dangerous_permissions": 16.2, "admin_operations": 15.0, "dynamic": 15.0,
    "telephony": 11.8, "root_detection": 11.5, "device_info": 7.0, "banking_targets": 11.5,
    "media_capture": 11.0, "network": 10.5, "crypto": 5.8, "location": 5.5,
    "file_operations": 3.0, "anti_debug": 5.3, "background_ops": 4.8,
    "native_code": 5.0, "reflection": 4.8, "obfuscation": 4.6, "modern_libs": 1.8,
    "privileged_ops": 8.5,
}

# -------------------- Graph & Meta Yazıcı --------------------

def build_api_graph_compact(apk_path, granularity='class', min_weight=2, keep_app_to_sdk_only=True):
    a, d, dx = AnalyzeAPK(str(apk_path))
    G = nx.DiGraph()
    cap_per_method = 50

    if isinstance(d, list):
        classes = []
        for dex in d:
            try: classes.extend(dex.get_classes())
            except: pass
    else:
        classes = d.get_classes()

    for cls in classes:
        try:
            c_name = cls.get_name()
            if c_name in STOP_CLASSES: continue
            for m in cls.get_methods():
                src = c_name
                try: xrefs = dx.get_method(m).get_xref_to()
                except: xrefs = m.get_xref_to()
                for i, (_, callee, _) in enumerate(xrefs):
                    if i >= cap_per_method: break
                    dst = callee.get_class_name()
                    if src == dst: continue
                    if G.has_edge(src, dst): G[src][dst]['weight'] += 1
                    else: G.add_edge(src, dst, weight=1)
        except: continue

    if min_weight > 1:
        G.remove_edges_from([(u,v) for u,v,dta in G.edges(data=True) if dta.get("weight",1) < min_weight])

    out_dir = Path("malware_graphs"); out_dir.mkdir(exist_ok=True)
    final_path = out_dir / (Path(apk_path).stem + ".graphml")
    nx.write_graphml(G, final_path)

    # Meta
    try:
        apk_size_kb = max(1, int(Path(apk_path).stat().st_size/1024))
        all_perms = list(set(a.get_permissions() or []))
        short_perms = [p.split(".")[-1] for p in all_perms]
        dangerous = sorted(set(short_perms) & DANGEROUS_PERMISSIONS)
        meta = {
            "apk_size_kb": apk_size_kb,
            "all_permissions": sorted(all_perms),
            "dangerous_permissions": dangerous,
            "danger_perm_hits": len(dangerous)
        }
        meta_path = out_dir / (Path(apk_path).stem + ".meta.json")
        with meta_path.open("w", encoding="utf-8") as f:
            json.dump(meta, f, ensure_ascii=False, indent=2)
    except:
        pass

    return G, str(final_path)

# -------------------- Yardımcı --------------------

def _squash(x: float, K: float = 120.0) -> float:
    """Aşırı yüksek semantik değerleri yumuşat (tanh tabanlı)."""
    if x <= 0:
        return 0.0
    return K * math.tanh(x / K)

# -------------------- Analizci --------------------

def analyze_malware_semantically(graph_path: str, debug: bool=False):
    # Graph
    try: G = nx.read_graphml(graph_path)
    except: return {"malware_score": 0.0}, None
    if not isinstance(G, nx.DiGraph): G = nx.DiGraph(G)
    N, E = G.number_of_nodes(), G.number_of_edges()
    if N == 0: return {"malware_score": 0.0}, None

    # Meta
    apk_size_kb = None; all_perm_shorts = []; danger_perm_hits = 0
    try:
        meta_path = Path(graph_path).with_suffix(".meta.json")
        if meta_path.exists():
            meta_full = json.load(open(meta_path, "r", encoding="utf-8"))
            apk_size_kb = int(meta_full.get("apk_size_kb") or 0) or None
            all_perm_shorts = [p.split(".")[-1] for p in meta_full.get("all_permissions", [])]
            danger_perm_hits = int(meta_full.get("danger_perm_hits") or 0)
    except:
        pass

    is_small = (apk_size_kb is not None and apk_size_kb <= 400)
    is_large = (apk_size_kb is not None and apk_size_kb >= 15000)
    benign_hint_hits = sum(1 for p in all_perm_shorts if p in BENIGN_HINT_PERMS) + \
                       sum(1 for p in all_perm_shorts if p == "C2D_MESSAGE")
    benign_heavy = benign_hint_hits >= 2

    # 1) Graph kanıtları
    counts_g = {k:0 for k in CATEGORY_RULES}
    for n in G.nodes():
        nstr = str(n)
        for cat, pats in CATEGORY_RULES.items():
            if any(p in nstr for p in pats):
                counts_g[cat] += 1

    # 2) Manifest sayımları
    counts_m = {k:0 for k in CATEGORY_RULES}
    if danger_perm_hits > 0:
        counts_m["dangerous_permissions"] += danger_perm_hits
    for p in all_perm_shorts:
        short = p.split(".")[-1]
        cat = PERM_TO_CATEGORY.get(p) or PERM_TO_CATEGORY.get(short)
        if cat:
            counts_m[cat] += 1
        if short == "C2D_MESSAGE":
            counts_m["background_ops"] += 1

    # 3) Manifest tavan/kısma
    caps_large = {"sms":1,"dangerous_permissions":3,"admin_operations":1,
                  "device_info":1,"file_operations":1,"background_ops":1,
                  "location":1,"media_capture":1,"privileged_ops":1}
    caps_normal = {"sms":2,"dangerous_permissions":6,"admin_operations":2,
                   "device_info":3,"file_operations":3,"background_ops":3,
                   "location":3,"media_capture":3,"privileged_ops":2}
    caps = caps_large if is_large else caps_normal
    for k,v in caps.items():
        if counts_m.get(k,0) > v:
            counts_m[k] = v

    # Kritiklerde graph şartı (large & benign)
    if is_large and benign_heavy:
        for k in ("sms","admin_operations"):
            if counts_g.get(k,0) == 0:
                counts_m[k] = 0

        # benign ipucunda manifest bazılarını ekstra kıs
        if counts_g.get("device_info",0)==0:
            counts_m["device_info"] = int(round(counts_m.get("device_info",0)*0.4))
        if counts_g.get("file_operations",0)==0:
            counts_m["file_operations"] = int(round(counts_m.get("file_operations",0)*0.4))
        if counts_g.get("background_ops",0)==0:
            counts_m["background_ops"] = int(round(counts_m.get("background_ops",0)*0.5))

    # 4) β seçimi
    if is_small:
        beta = 0.55
    elif is_large or benign_heavy:
        beta = 0.10
    else:
        beta = 0.25

    # 5) Semantik skorlar (ayrı)
    sem_g_raw = sum(W.get(cat,1.0)*counts_g[cat] for cat in counts_g)
    sem_m_raw = sum(W.get(cat,1.0)*counts_m[cat] for cat in counts_m)
    sem_raw = sem_g_raw + beta*sem_m_raw

    # 6) Normalizasyon ve squash
    norm = 1.0 + (N/400.0) + (E/800.0)
    sem_normed = sem_raw / norm
    sem = _squash(sem_normed, K=120.0)

    # 7) Yapısal skor (zayıflaştırılmış)
    try: max_out = max((d for _, d in G.out_degree()), default=0)
    except: max_out = 0
    try: dens = nx.density(G)
    except: dens = 0.0
    structural = 0.6*(0.2*(math.log1p(E)+math.log1p(N)) + 0.5*math.log1p(max_out) + 2.0*dens)

    # 8) Heuristik bonuslar (yumuşak)
    bonus = 0.0
    CRIT = ("sms","admin_operations","dynamic","dangerous_permissions")
    crit_hits = sum(1 for k in CRIT if counts_g.get(k,0)+counts_m.get(k,0) > 0)
    if crit_hits >= 2: bonus += 4.0

    total_cat_hits = sum(counts_g.values()) + sum(counts_m.values())
    risk_core = (counts_g.get("sms",0)+counts_m.get("sms",0)) + \
                (counts_g.get("admin_operations",0)+counts_m.get("admin_operations",0)) + \
                (counts_g.get("dynamic",0)+counts_m.get("dynamic",0))
    ratio = (risk_core/total_cat_hits) if total_cat_hits>0 else 0.0
    if ratio >= 0.30: bonus += 2.0
    elif ratio >= 0.20: bonus += 1.0

    if (counts_g.get("sms",0)>0 or counts_g.get("device_info",0)>0) and \
       (counts_g.get("sms",0)+counts_m.get("sms",0) > 0) and \
       (counts_g.get("device_info",0)+counts_m.get("device_info",0) > 1):
        bonus += 2.0
    if (counts_g.get("admin_operations",0)>0 or counts_g.get("crypto",0)>0) and \
       (counts_g.get("admin_operations",0)+counts_m.get("admin_operations",0) > 0) and \
       (counts_g.get("crypto",0)+counts_m.get("crypto",0) > 1):
        bonus += 2.0

    # 9) Boyut çarpanı
    mult = 1.0
    if apk_size_kb is not None:
        if apk_size_kb <= 1000: mult *= 1.1
        elif apk_size_kb >= 50000: mult *= 0.95
        elif apk_size_kb >= 15000: mult *= 0.92

    total = float(max(0.0, sem + bonus) * mult + structural)

    if debug:
        print("[DEBUG] size_kb=", apk_size_kb, "beta=", beta,
              "benign_hints=", benign_hint_hits, "large=", is_large,
              "| sem_g_raw=", round(sem_g_raw,2), "sem_m_raw=", round(sem_m_raw,2),
              "norm=", round(norm,3), "sem_normed=", round(sem_normed,2),
              "sem_squash=", round(sem,2),
              "| struct=", round(structural,2), "bonus=", round(bonus,2),
              "| total=", round(total,2))

    return {"malware_score": total}, None
