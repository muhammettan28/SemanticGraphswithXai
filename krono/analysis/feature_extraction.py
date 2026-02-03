#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Android APK Feature Extraction for ML
Minimal version - only essential features
"""

from __future__ import annotations
from pathlib import Path
from typing import Dict
import networkx as nx
import json
import sys
from analysis import packing
from analysis import graph_features as gf
from analysis import api_patterns as AP
try:
    from androguard.misc import AnalyzeAPK
    import logging
    logging.getLogger("androguard").setLevel(logging.WARNING)
    try:
        from loguru import logger
        logger.remove()
        logger.add(sys.stderr, level="WARNING")
    except ImportError:
        pass
except ImportError:
    print("Hata: Androguard kütüphanesi bulunamadı.")
    exit(1)


# ============ MINIMAL CONSTANTS (embedded) ============

# Stop classes to filter out noise
STOP_CLASSES = frozenset([
    "Ljava/lang/Object;", "Ljava/lang/String;", "Ljava/lang/StringBuilder;",
    "Landroid/view/View;", "Landroid/app/Activity;", "Landroid/content/Context;",
])

# Dangerous permissions
DANGEROUS_PERMISSIONS = frozenset([
    "SEND_SMS", "READ_SMS", "RECEIVE_SMS", "RECEIVE_WAP_PUSH", "RECEIVE_MMS",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "CALL_PHONE",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "ANSWER_PHONE_CALLS",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "CAMERA", "RECORD_AUDIO",
    "WRITE_EXTERNAL_STORAGE", "READ_EXTERNAL_STORAGE",
    "BIND_DEVICE_ADMIN", "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE",
    "GET_TASKS", "KILL_BACKGROUND_PROCESSES", "INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
    "CHANGE_WIFI_STATE", "CHANGE_NETWORK_STATE", "ACCESS_WIFI_STATE"
])

# Comprehensive API patterns (30 categories - highly discriminative for malware detection)

# Comprehensive benign library prefixes (merged from all sources - 150+ libraries)
BENIGN_LIBS = frozenset([
    # === Google/Android Official ===
    'Landroidx/', 'Lcom/google/android/', 'Lcom/google/firebase/', 'Lcom/google/common/',
    'Lcom/google/gson/', 'Lcom/google/crypto/', 'Lcom/google/zxing/', 'Lcom/google/protobuf/',
    'Lcom/android/volley/', 'Lcom/google/dagger/', 'Lcom/google/mlkit/', 'Lcom/google/ar/',
    'Lcom/google/flatbuffers/', 'Lcom/google/tink/', 'Lcom/google/android/exoplayer2/',
    'Lcom/google/android/datatransport/', 'Lcom/google/android/play/', 'Lcom/google/android/material/',
    'Lcom/google/android/gms/', 'Lcom/google/android/flexbox/', 'Lcom/google/mediapipe/',

    # === Kotlin/JVM Languages ===
    'Lkotlin/', 'Lkotlinx/', 'Lscala/', 'Lgroovy/', 'Lorg/jetbrains/', 'Lkotlinx/serialization/',
    'Lkotlinx/coroutines/',

    # === Networking Libraries ===
    'Lcom/squareup/okhttp', 'Lcom/squareup/retrofit', 'Lokhttp3/', 'Lretrofit2/', 'Lcom/squareup/okio/',
    'Lcom/squareup/moshi/', 'Lio/reactivex/', 'Lio/netty/', 'Lorg/apache/http/', 'Lio/grpc/',
    'Lio/ktor/', 'Lorg/eclipse/paho/',

    # === UI/Image Processing ===
    'Lcom/bumptech/glide/', 'Lcom/squareup/picasso/', 'Lcom/facebook/fresco/',
    'Lcom/nostra13/universalimageloader/', 'Lcom/github/bumptech/', 'Lcom/airbnb/lottie/',
    'Lio/coil-kt/', 'Lcoil/', 'Lcom/github/chrisbanes/photoview/', 'Lde/hdodenhof/circleimageview/',
    'Ljp/wasabeef/glide/', 'Lcom/github/barteksc/pdfviewer/', 'Lcom/caverock/androidsvg/',

    # === Social/Analytics/Ads ===
    'Lcom/facebook/', 'Lcom/twitter/', 'Lcom/linkedin/', 'Lcom/instagram/', 'Lcom/crashlytics/',
    'Lio/fabric/', 'Lcom/flurry/', 'Lcom/mixpanel/', 'Lcom/amplitude/', 'Lcom/segment/analytics/',
    'Lcom/appsflyer/', 'Lcom/adjust/sdk/', 'Lcom/microsoft/appcenter/', 'Lio/sentry/',
    'Lcom/bugsnag/android/', 'Lcom/instabug/', 'Lcom/optimizely/', 'Lcom/launchdarkly/',
    'Lcom/google/ads/', 'Lcom/google/android/ump/', 'Lcom/facebook/ads/', 'Lcom/mopub/',
    'Lcom/applovin/', 'Lcom/unity3d/ads/', 'Lcom/vungle/', 'Lcom/chartboost/', 'Lcom/inmobi/',
    'Lcom/ironsource/', 'Lcom/tapjoy/', 'Lcom/startapp/', 'Lcom/bytedance/sdk/openadsdk/',

    # === Payment SDKs ===
    'Lcom/stripe/android/', 'Lcom/paypal/android/', 'Lcom/braintreepayments/', 'Lcom/adyen/',
    'Lcom/squareup/reader/', 'Lcom/google/android/gms/wallet/',

    # === Database/ORM ===
    'Lio/realm/', 'Lcom/j256/ormlite/', 'Lcom/raizlabs/android/dbflow/', 'Lorg/greenrobot/greendao/',

    # === Dependency Injection ===
    'Ldagger/', 'Ljavax/inject/', 'Lorg/koin/', 'Lcom/google/dagger/hilt/',

    # === Reactive/Async ===
    'Lio/reactivex/', 'Lrx/', 'Lorg/reactivestreams/', 'Lkotlinx/coroutines/',

    # === Common Java/Apache ===
    'Lorg/apache/', 'Lorg/json/', 'Lorg/slf4j/', 'Lorg/w3c/', 'Lch/qos/logback/',
    'Ljakarta/', 'Ljavax/annotation/', 'Lcom/fasterxml/jackson/', 'Lcom/google/guava/',
    'Lorg/bouncycastle/', 'Lorg/simpleframework/', 'Lorg/jsoup/',

    # === Testing Frameworks ===
    'Lorg/junit/', 'Lorg/mockito/', 'Lorg/hamcrest/', 'Landroidx/test/', 'Lorg/robolectric/',
    'Lio/mockk/',

    # === Cross-Platform Frameworks ===
    'Lio/flutter/', 'Lcom/facebook/react/', 'Lorg/apache/cordova/', 'Lmono/android/',
    'Lcom/getcapacitor/', 'Lcom/telerik/',

    # === AWS/Cloud Services ===
    'Lcom/amazonaws/', 'Lcom/microsoft/azure/', 'Lcom/huawei/hms/', 'Lcom/mapbox/',

    # === Misc Popular Libraries ===
    'Lbutterknife/', 'Lcom/jakewharton/', 'Lcom/squareup/leakcanary/', 'Lcom/android/installreferrer/',
    'Lcom/journeyapps/barcodescanner/', 'Lcom/unity3d/', 'Lcom/google/android/horologist/',
    'Lcom/airbnb/epoxy/', 'Lcom/facebook/shimmer/', 'Lcom/github/mikephil/charting/',
    'Lorg/tensorflow/lite/', 'Lcom/auth0/', 'Lcom/microsoft/identity/',
])


# ============ FUNCTIONS ============

def build_api_graph_compact(apk_path: str, min_weight: int = 1) -> tuple[dict, Path]:
    """Build API call graph and extract API counts accurately from methods/strings"""
    out_dir = Path("./graph_files")
    out_dir.mkdir(exist_ok=True)
    base_name = Path(apk_path).stem
    graph_path = out_dir / f"{base_name}.graphml"
    meta_path = out_dir / f"{base_name}.meta.json"

    # Önbellek kontrolü (İstersen burayı geçici olarak devre dışı bırakıp yeniden çalıştır)
    if graph_path.exists() and meta_path.exists():
        try:
            with meta_path.open("r") as f:
                return json.load(f), graph_path
        except:
            pass

    # 1. APK Analizi
    try:
        a, _, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        print(f"Hata analiz edilemedi {apk_path}: {e}")
        return {}, graph_path

    # --- YENİ BÖLÜM: API ve String Pattern Eşleştirme ---
    # Sadece class isimlerine değil, metot çağrılarına ve stringlere bakıyoruz.

    api_counts = {cat: 0 for cat in AP.API_PATTERNS.keys()}

    # A) Metot Çağrılarını Tara (External Method Calls)
    # Kodun dışarıdaki hangi API'leri çağırdığına bakar (Örn: java.lang.Runtime.exec)
    for method in dx.get_methods():
        if method.is_external():
            full_name = str(method.get_method())  # Örn: Ljava/lang/Runtime;->exec
            name_only = method.name  # Örn: exec
            class_only = method.get_class_name()  # Örn: Ljava/lang/Runtime;

            for cat, patterns in AP.API_PATTERNS.items():
                for pat in patterns:
                    # Hem tam imzaya, hem sadece isme bak (Pattern tipine göre yakalar)
                    if pat in full_name or pat in name_only:
                        api_counts[cat] += 1

    # B) String Sabitlerini Tara (Örn: "su", "/system/bin/sh", "root")
    # Özellikle root detect ve shell komutları için kritiktir.
    for s in dx.get_strings():
        val = s.get_value()
        if not val: continue

        for cat, patterns in AP.API_PATTERNS.items():
            # Root ve Shell kategorileri stringlere daha çok bağımlıdır
            if cat in ['root_detect', 'shell', 'ransomware', 'anti_vm']:
                for pat in patterns:
                    if pat in val:
                        api_counts[cat] += 1

    # --- GRAF OLUŞTURMA (Eski mantık devam ediyor) ---
    cg = dx.get_call_graph()
    G = nx.DiGraph()

    for edge in cg.edges(data=True):
        src = edge[0].class_name
        dst = edge[1].class_name
        if src in STOP_CLASSES or dst in STOP_CLASSES:
            continue
        # Self-loop engellemek istersen: if src == dst: continue
        if G.has_edge(src, dst):
            G[src][dst]['weight'] += 1
        else:
            G.add_edge(src, dst, weight=1)

    G.remove_edges_from([(u, v) for u, v, d in G.edges(data=True) if d.get("weight", 1) < min_weight])
    G.remove_nodes_from(list(nx.isolates(G)))

    nx.write_graphml(G, str(graph_path.with_suffix('.graphml.tmp')))
    graph_path.with_suffix('.graphml.tmp').rename(graph_path)

    # Metadata oluşturma (Artık api_counts'u da içeriyor)
    all_perms = list(a.get_permissions())
    meta = {
        'apk_name': Path(apk_path).name,
        'apk_size_kb': round(Path(apk_path).stat().st_size / 1024.0, 2),
        'all_permissions': sorted(all_perms),
        'dangerous_permissions': sorted([p.split('.')[-1] for p in all_perms
                                         if p.split('.')[-1] in DANGEROUS_PERMISSIONS]),
        'api_counts': api_counts,  # <--- HESAPLANAN SKORLAR BURADA
        'is_packed': 1 if packing.is_likely_packed_with_androguard(apk_path) else 0
    }

    with meta_path.with_suffix('.json.tmp').open("w") as f:
        json.dump(meta, f, indent=2)
    meta_path.with_suffix('.json.tmp').rename(meta_path)

    return meta, graph_path


def extract_features(graph_path: str | Path, apk_path: str | Path) -> Dict:
    graph_path = Path(graph_path)
    meta_path = graph_path.with_suffix(".meta.json")

    try:
        G = nx.read_graphml(graph_path)
        with meta_path.open("r") as f:
            meta = json.load(f)
    except Exception as e:
        return {"apk_name": Path(apk_path).name, "error": str(e)}

    N = G.number_of_nodes()
    E = G.number_of_edges()

    features = {
        'apk_name': meta['apk_name'],
        'apk_size_kb': meta.get('apk_size_kb', 0),
        'node_count': N,
        'edge_count': E,
        'is_packed': meta.get('is_packed', 0),
        'dangerous_perm_count': len(meta.get('dangerous_permissions', [])),
    }

    # API Counts'u doğrudan meta'dan al
    api_counts = meta.get('api_counts', {})
    for cat, count in api_counts.items():
        features[f'api_{cat}'] = count

    # Graph metriklerini ekle
    if N > 0:
        features.update(gf.compute_graph_metrics(G))
    else:
        features.update({
            'density': 0.0, 'avg_betweenness': 0.0, 'avg_clustering': 0.0,
            'pagerank_max': 0.0, 'avg_in_degree': 0.0, 'avg_out_degree': 0.0
        })

    # Benign Ratio (Hala graf üzerinden hesaplanabilir)
    nodes_str = [str(n) for n in G.nodes()]
    benign_count = sum(1 for node in nodes_str if any(node.startswith(lib) for lib in BENIGN_LIBS))
    features['benign_ratio'] = benign_count / N if N > 0 else 0.0

    return features
