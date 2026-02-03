import sys
import zipfile
from androguard.misc import AnalyzeAPK
import os


def inspect_apk_zip_minimal(apk_path: str):
    info = {"total_files": 0, "dex_files": [], "libs": [], "assets": [], "large_files": []}
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            size = z.getinfo(name).file_size
            info["total_files"] += 1
            if name.endswith(".dex"):
                info["dex_files"].append((name, size))
            elif name.startswith("lib/"):
                info["libs"].append((name, size))
            elif name.startswith("assets/"):
                info["assets"].append((name, size))
            if size > 5 * 1024 * 1024:  # 5 MB üstü
                info["large_files"].append((name, size))
    return info



def _all_strings_from_dx(d_list):
    all_strings = set()
    for d in d_list:
        try:
            for s in d.get_strings():
                try:
                    all_strings.add(s.get_value())
                except Exception:
                    all_strings.add(str(s))
        except Exception:
            continue
    return all_strings


def has_suspicious_combination(dx) -> bool:
    """Şüpheli kombinasyonları kontrol et"""
    try:
        # Gerekli sınıf ve metod isimlerini ara
        dex_class_loader = False
        reflection = False
        native = False
        
        for method in dx.get_methods():
            method_str = method.get_method().get_class_name() + "->" + method.get_method().get_name()
            
            if "DexClassLoader" in method_str:
                dex_class_loader = True
            if "reflect" in method_str.lower():
                reflection = True
            if "native" in method_str.lower() or "jni" in method_str.lower():
                native = True
                
            # Tüm şüpheli özellikler bulunduysa erken çık
            if dex_class_loader and (reflection or native):
                return True
                
        return False
        
    except Exception as e:
        print(f"[WARN] Şüpheli kombinasyon kontrolü başarısız: {e}")
        return False



def is_likely_packed_with_androguard(apk_path: str) -> bool:
    """
    Androguard kullanarak bir APK'nın paketlenmiş veya gizlenmiş olma olasılığını
    statik olarak analiz eder. (BaiduProtect ve Jiagu dahil)
    """
    try:
        try:
            apk_size_mb = os.path.getsize(apk_path) / (1024 * 1024)
        except Exception:
            apk_size_mb = 10  # Okunamazsa, varsayılan olarak büyük kabul et

        a, d_list, dx = AnalyzeAPK(apk_path)

        # KURAL 1: TİCARİ PAKETLEYİCİ TESPİTİ (EN GÜÇLÜ SİNYAL)
        # ----------------------------------------------------------------------
        
        # 1a. Jiagu native kütüphaneleri (Dosya yolu tam eşleşmeli, bu güvenlidir)
        jiagu_libs = ["libjiagu.so", "libjiagu_a64.so", "libjgbibc_32.so", "libjgbibc_64.so"]
        apk_libs = a.get_libraries()
        if any(any(lib.endswith(jiagu_lib) for jiagu_lib in jiagu_libs) for lib in apk_libs):
            print(f"[!] Yüksek Güvenilirlikli Paketleyici (Dosya): Jiagu native kütüphanesi tespit edildi -> {apk_path}")
            return True

        # 1b. BaiduProtect native kütüphaneleri (Dosya yolu tam eşleşmeli, bu güvenlidir)
        baidu_libs = ["libbaiduprotect.so", "libbdmain.so", "libBaiduProtect.so"]
        if any(any(lib.endswith(baidu_lib) for baidu_lib in baidu_libs) for lib in apk_libs):
            print(f"[!] Yüksek Güvenilirlikli Paketleyici (Dosya): BaiduProtect native kütüphanesi tespit edildi -> {apk_path}")
            return True

        # 1c. Paketleyici asset (varlık) dosyaları (Dosya yolu tam eşleşmeli, bu güvenlidir)
        packer_assets = [
            "jiagu_data.bin", "jiagu_art", "ijm_lib", ".jiagu", "jiagu.db", # Jiagu
            "baidu_dex.jar", "baiduprotect.dat", "baiduprotect.jar" # Baidu
        ]
        asset_list = a.get_files()
        if any(any(asset in file_path for file_path in asset_list) for asset in packer_assets):
            print(f"[!] Yüksek Güvenilirlikli Paketleyici (Dosya): Paketleyici asset dosyası tespit edildi -> {apk_path}")
            return True

        # --- YENİ DÜZELTME (BU BÖLÜM DEĞİŞTİ) ---
        
        # Kural 1d (String Search) - En "gürültülü" (en çok false positive) kural budur.
        # Bu kuralı SADECE KÜÇÜK (10MB altı) APK'lar için çalıştır.
        string_search_limit_mb = 10.0 
        
        if apk_size_mb < string_search_limit_mb:
            generic_packer_strings = [
                "com.bangcle", "com.secneo", "com.tencent.legu", "com.qihoo360.protect",
                "com.baidu.protect" 
            ]
            for d in d_list:
                for s in d.get_strings():
                    if any(packer in s for packer in generic_packer_strings):
                        print(f"[!] Yüksek Güvenilirlikli Paketleyici (String): Bilinen paketleyici imzası bulundu ({s}) -> {apk_path}")
                        return True
        else:
            # 12MB'lık APK'mız bu bloğa girecek ve kuralı atlayacak.
            print(f"[INFO] Büyük APK ({apk_size_mb:.1f}MB), Kural 1d (string taraması) atlanıyor.")

        # Kural 2 & 3 (Davranışsal) - Bunlar orta boyutlu APK'lar (15MB altı) için çalışabilir.
        behavioral_limit_mb = 5.0
        
        if apk_size_mb < behavioral_limit_mb:
            
            # KURAL 2: ŞÜPHELİ DAVRANIŞSAL DESENLER
            if has_suspicious_combination(dx):
                print(f"[!] Olası Paketleyici (Davranışsal): Şüpheli kombinasyon (DexClassLoader+Reflect/Native) -> {apk_path}")
                return True

            # KURAL 3: GELİŞTİRİLMİŞ ÖZEL APPLICATION SINIFI TESPİTİ
            app_class_name = a.get_attribute_value('application', 'name')
            if app_class_name and app_class_name not in ["android.app.Application", "androidx.multidex.MultiDexApplication"]:
                formatted_name = "L" + app_class_name.replace('.', '/') + ";"
                try:
                    app_class = dx.get_class_analysis(formatted_name)
                    if app_class:
                        class_strings = {s.get_value() for s in app_class.get_strings()}
                        if "Ldalvik/system/DexClassLoader;" in class_strings and "Ljavax/crypto/Cipher;" in class_strings:
                            print(f"[!] Olası Paketleyici (Davranışsal): Özel Application sınıfı ({formatted_name}) İÇİNDE şifreleme ve kod yükleme tespit edildi -> {apk_path}")
                            return True
                except Exception:
                    pass
        


    except Exception as e:
        print(f"[Androguard Analiz Hatası] {apk_path}: {e}", file=sys.stderr)

    return False