#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PARALLEL Batch Feature Extraction for XGBoost Training
Mac'te 12 CPU ile optimize edilmiş
"""

import argparse
import os
import sys
import csv
import time
import traceback
import zipfile
from pathlib import Path
from multiprocessing import Pool, cpu_count, current_process
from datetime import datetime

# Feature extraction modülünü import et
from analysis.feature_extraction import build_api_graph_compact, extract_features


# Feature names (49 features total)
FEATURE_NAMES = [
    'apk_name', 'apk_size_kb', 'node_count', 'edge_count', 'is_packed',
    'density', 'avg_betweenness', 'avg_clustering', 'pagerank_max', 'avg_in_degree', 'avg_out_degree',
    'api_exfiltration', 'api_keylog', 'api_admin', 'api_shell', 'api_accessibility_abuse',
    'api_overlay', 'api_ransomware',
    'api_sms', 'api_telephony', 'api_anti_debug', 'api_obfuscation', 'api_anti_vm', 'api_packer_check',
    'api_dynamic_load', 'api_screenshot', 'api_clipboard', 'api_persistence', 'api_hooking',
    'api_network', 'api_stealth',
    'api_location', 'api_camera', 'api_microphone', 'api_crypto', 'api_reflection',
    'api_device_info', 'api_contacts', 'api_root_detect',
    'api_file_ops', 'api_webview', 'api_sqlite', 'api_native_code', 'api_background',
    'api_biometric', 'api_notification_abuse', 'api_vpn', 'api_browser_exploit', 'api_app_ops',
    'benign_ratio', 'dangerous_perm_count'
]


def process_single_apk(task):
    """Tek bir APK'yı işle (multiprocessing worker)"""
    apk_path, label, done_set = task
    proc_name = current_process().name
    apk_name = apk_path.name
    
    # Resume kontrolü
    if apk_name in done_set:
        return None, None, f"SKIP: {apk_name} (already processed)"
    
    try:
        # Dosya boyutu kontrolü
        size = os.path.getsize(apk_path)
        if size < 50 * 1024:  # 50 KB
            return None, 'small', f"[{proc_name}] SKIP-SMALL: {apk_name} ({size} bytes)"
        
        # ZIP kontrolü
        try:
            with zipfile.ZipFile(apk_path, 'r') as zf:
                if zf.testzip() is not None:
                    return None, 'badzip', f"[{proc_name}] BAD-ZIP: {apk_name}"
        except zipfile.BadZipFile:
            return None, 'badzip', f"[{proc_name}] BAD-ZIP: {apk_name}"
        
        # 1. Graph oluştur
        try:
            meta, graph_path = build_api_graph_compact(str(apk_path))
        except Exception as e:
            return None, 'graph_error', f"[{proc_name}] ❌ {apk_name}: Graph build error - {type(e).__name__}"
        
        if not graph_path or not Path(graph_path).exists():
            return None, 'graph_error', f"[{proc_name}] ❌ {apk_name}: Graph file not created"
        
        # 2. Feature extraction
        try:
            features = extract_features(graph_path, str(apk_path))
        except Exception as e:
            return None, 'feature_error', f"[{proc_name}] ❌ {apk_name}: Feature extraction error - {type(e).__name__}"
        
        if "error" in features:
            return None, 'feature_error', f"[{proc_name}] ❌ {apk_name}: {features.get('error')}"
        
        # Feature row oluştur
        row = [features.get(fn, 0) for fn in FEATURE_NAMES] + [label]
        
        print(f"[{proc_name}] ✅ {apk_name}")
        return row, None, None
        
    except Exception as e:
        return None, 'unexpected', f"[{proc_name}] ❌ {apk_name}: {type(e).__name__}: {str(e)}"


def iter_dataset_apks(dataset_dir: Path, subset: str = None):
    """APK listesini oluştur"""
    benign_dir = dataset_dir / "benign"
    malware_dir = dataset_dir / "malware"
    
    apks = []
    
    if subset in (None, "benign") and benign_dir.exists():
        for p in sorted(benign_dir.glob("*.apk")):
            apks.append((p, 0))
    
    if subset in (None, "malware") and malware_dir.exists():
        for p in sorted(malware_dir.glob("*.apk")):
            apks.append((p, 1))
    
    return apks


def load_done_set(csv_path: Path) -> set:
    """Resume için işlenmiş APK'ları yükle"""
    done = set()
    if not csv_path.exists():
        return done
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                apk_name = row.get('apk_name')
                if apk_name:
                    done.add(apk_name)
    except Exception:
        pass
    
    return done


def init_csv(output_csv: Path):
    """CSV header oluştur"""
    if output_csv.exists():
        return
    
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(output_csv, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(FEATURE_NAMES + ['label'])


def batch_extract_parallel(dataset_dir: Path, out_csv: Path, subset: str = None, 
                          limit: int = None, num_processes: int = None):
    """Paralel feature extraction"""
    
    # CPU sayısını belirle (Mac'te 12 CPU var)
    if num_processes is None:
        num_processes = max(1, cpu_count() - 2)  # 2 çekirdek sisteme bırak
    
    print("=" * 60)
    print("🚀 PARALLEL FEATURE EXTRACTION")
    print("=" * 60)
    print(f"💻 CPU cores: {cpu_count()} (using {num_processes})")
    print(f"📁 Dataset: {dataset_dir}")
    print(f"💾 Output: {out_csv}")
    print(f"🕒 Start: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # CSV hazırla
    init_csv(out_csv)
    
    # Resume: zaten işlenmiş APK'ları yükle
    done_set = load_done_set(out_csv)
    print(f"📋 Already processed: {len(done_set)} APKs")
    
    # APK listesi
    apk_list = iter_dataset_apks(dataset_dir, subset)
    
    if limit:
        apk_list = apk_list[:limit]
    
    # Task'lara done_set'i ekle
    tasks = [(apk_path, label, done_set) for apk_path, label in apk_list]
    total_tasks = len(tasks)
    
    print(f"📦 Total APKs: {total_tasks}")
    print(f"📦 To process: {total_tasks - len(done_set)}")
    print("=" * 60)
    
    # İstatistikler
    start_time = time.time()
    success_count = 0
    error_counts = {'small': 0, 'badzip': 0, 'graph_error': 0, 
                   'feature_error': 0, 'unexpected': 0}
    
    # Multiprocessing pool
    with Pool(processes=num_processes) as pool:
        with open(out_csv, 'a', newline='', encoding='utf-8') as csv_file:
            csv_writer = csv.writer(csv_file)
            
            # Progress tracking
            for i, result in enumerate(pool.imap_unordered(process_single_apk, tasks), 1):
                row, error_type, message = result
                
                if row is not None:
                    csv_writer.writerow(row)
                    csv_file.flush()
                    success_count += 1
                elif error_type:
                    error_counts[error_type] += 1
                    if message and i <= 10:  # İlk 10 hatayı göster
                        print(message)
                
                # İlerleme göster (her 50 APK'da bir)
                if i % 50 == 0 or i == total_tasks:
                    elapsed = time.time() - start_time
                    rate = i / elapsed if elapsed > 0 else 0
                    remaining = (total_tasks - i) / rate if rate > 0 else 0
                    
                    print(f"[{i}/{total_tasks}] "
                          f"✅ {success_count} | "
                          f"❌ {sum(error_counts.values())} | "
                          f"⏱️  {remaining/60:.1f} min remaining | "
                          f"📊 {rate:.1f} APK/sec")
    
    # Özet
    elapsed_total = time.time() - start_time
    print("\n" + "=" * 60)
    print("🏁 EXTRACTION COMPLETED")
    print("=" * 60)
    print(f"✅ Success: {success_count}")
    print(f"❌ Errors: {sum(error_counts.values())}")
    for error_type, count in error_counts.items():
        if count > 0:
            print(f"   - {error_type}: {count}")
    print(f"⏱️  Total time: {elapsed_total/60:.1f} minutes")
    print(f"📊 Speed: {success_count/(elapsed_total/60):.1f} APK/min")
    print(f"💾 Output: {out_csv}")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Parallel APK Feature Extraction (Mac optimized)")
    parser.add_argument("--dataset", required=True, type=Path, help="Dataset directory (contains benign/malware)")
    parser.add_argument("--out", required=True, type=Path, help="Output CSV path")
    parser.add_argument("--subset", choices=["benign", "malware"], default=None, help="Process only one subset")
    parser.add_argument("--limit", type=int, default=None, help="Max APKs to process (for testing)")
    parser.add_argument("--processes", type=int, default=None, help="Number of parallel processes (default: CPU-2)")
    args = parser.parse_args()
    
    batch_extract_parallel(args.dataset, args.out, subset=args.subset, 
                          limit=args.limit, num_processes=args.processes)


if __name__ == "__main__":
    main()
