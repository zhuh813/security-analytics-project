import pandas as pd
import numpy as np
from scipy import stats

def run_cyber_analytics():
    print("="*70)
    print("[Data Science Pipeline] 啟動 DDoS 流量統計學特徵工程分析...")
    print("="*70)
    
    # 1. 讀取與清洗數據
    csv_path = r"C:\Users\TMP-214\Desktop\資安分析專題\DDoS-Friday-Clean.csv"
    print(f"[步驟 1/4] 正在加載大數據集: {csv_path} ...")
    df = pd.read_csv(csv_path)
    
    # 清洗數值欄位雜質 (如文字 Infinity)
    df['Flow Packets/s'] = pd.to_numeric(df['Flow Packets/s'], errors='coerce')
    df = df.dropna()
    
    # 定義應變數 Y (1 為 DDoS, 0 為 Benign 正常流量)
    df['target'] = df['Label'].apply(lambda x: 1 if x == 'DDoS' else 0)
    
    # 2. 相關度分析 (Correlation Analysis)
    print("\n[步驟 2/4] 正在計算自變數特徵與 DDoS 應變數之 Pearson 相關係數...")
    numeric_df = df.select_dtypes(include=[np.number])
    correlations = numeric_df.corr()['target'].abs().sort_values(ascending=False)
    
    print("\n【特徵相關度分析結果 - Top 3 黃金特徵】")
    # 排除 target 自身
    top_features = correlations.index[1:4]
    for idx, feat in enumerate(top_features, 1):
        print(f" 🌟 排名 {idx}: 特徵欄位 [{feat}] -> 相關係流絕對值: {correlations[feat]:.4f}")
        
    # 3. 假設檢定 (Hypothesis Testing) - 獨立樣本 t 檢定
    print("\n[步驟 3/4] 針對關鍵流量特徵進行雙組獨立樣本 t 檢定 (Benign vs DDoS)...")
    test_feat = 'Flow Packets/s'
    group_benign_test = df[df['target'] == 0][test_feat]
    group_ddos_test = df[df['target'] == 1][test_feat]
    
    t_stat, p_val = stats.ttest_ind(group_benign_test, group_ddos_test, equal_var=False)
    print(f"\n【流量突變顯著性檢定報告 - 欄位: {test_feat}】")
    print(f" 📊 正常組(Benign) 平均每秒封包數: {group_benign_test.mean():.2f} pps")
    print(f" 📊 攻擊組(DDoS)   平均每秒封包數: {group_ddos_test.mean():.2f} pps")
    print(f" 🔬 t 統計量: {t_stat:.4f} | p-value: {p_val}")
    
    if p_val < 0.05:
        print(" 📌 統計結論: 拒絕虛無假設！兩組群體具備顯著統計差異。該特徵通過『防禦特徵篩選』。")
    else:
        print(" 📌 統計結論: 無顯著差異。")
        
    # 4. 推導動態防禦閾值 (Threshold Derivation) —— 【此處已修正優化】
    # 改用排名第 1 且與 DDoS 呈現高度正相關的黃金特徵：Bwd Packet Length Mean
    target_feat = 'Bwd Packet Length Mean'
    print(f"\n[步驟 4/4] 依據黃金特徵 [{target_feat}] 之統計分佈，推導 SOAR 動態聯防決策閾值...")
    
    group_benign = df[df['target'] == 0][target_feat]
    group_ddos = df[df['target'] == 1][target_feat]
    
    mu_benign = group_benign.mean()
    sigma_benign = group_benign.std()
    
    # 正常組 3倍標準差以外 (涵蓋 99.7% 正常行為)
    high_threshold = mu_benign + 3 * sigma_benign
    
    # 惡意流量的中位數 (切入惡意流量核心攻擊區間)
    critical_threshold = group_ddos.median() 
    
    print(f"\n【資安科學化決策閾值產出 - 修正版】")
    print(f" ⚠️  HIGH 風險閾值 (偏離正常基準 3σ): > {high_threshold:.2f} bytes")
    print(f" 🚨 CRITICAL 崩潰閾值 (進入惡意核心區間): > {critical_threshold:.2f} bytes")
    print("="*70)

if __name__ == "__main__":
    run_cyber_analytics()