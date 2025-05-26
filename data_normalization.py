import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os

def min_max_normalize(scores):
    """对分数进行最小-最大归一化（0-1范围）"""
    min_score = min(scores)
    max_score = max(scores)
    
    # 防止除以零（如果所有分数相同）
    if max_score == min_score:
        return [0.5] * len(scores)  # 如果所有值相同，返回中间值0.5
    
    normalized = [(score - min_score) / (max_score - min_score) for score in scores]
    return normalized

def determine_thresholds(normalized_scores, actions):
    """根据action类别确定阈值"""
    # 将数据按action分组
    allow_scores = [score for score, action in zip(normalized_scores, actions) if action.lower() == 'allow']
    request_scores = [score for score, action in zip(normalized_scores, actions) if action.lower() == 'challenge']
    reject_scores = [score for score, action in zip(normalized_scores, actions) if action.lower() == 'reject']
    
    # 检查是否有足够的数据来确定阈值
    if not allow_scores or not request_scores or not reject_scores:
        print("警告：某些风险类别没有足够的数据样本")
        print(f"Allow样本数: {len(allow_scores)}")
        print(f"Challenge样本数: {len(request_scores)}")
        print(f"Reject样本数: {len(reject_scores)}")
        
        # 如果缺少数据，使用简单的百分比划分
        all_scores = sorted(normalized_scores)
        lower_threshold = all_scores[int(len(all_scores) * 0.33)]
        upper_threshold = all_scores[int(len(all_scores) * 0.66)]
        return lower_threshold, upper_threshold
    
    # 计算每个组的统计信息
    allow_max = max(allow_scores) if allow_scores else 0
    request_min = min(request_scores) if request_scores else 0.33
    request_max = max(request_scores) if request_scores else 0.66
    reject_min = min(reject_scores) if reject_scores else 0.67
    
    # 确定阈值（allow和request之间，request和reject之间）
    lower_threshold = (allow_max + request_min) / 2
    upper_threshold = (request_max + reject_min) / 2
    
    return lower_threshold, upper_threshold

def assign_risk_level(score, lower_threshold, upper_threshold):
    """根据阈值分配风险等级"""
    if score < lower_threshold:
        return "低风险"
    elif score < upper_threshold:
        return "中等风险"
    else:
        return "高风险"

def plot_distribution(normalized_scores, actions, lower_threshold, upper_threshold, output_dir):
    """绘制分数分布图和阈值"""
    plt.figure(figsize=(10, 6))
    
    # 按action分组绘制直方图
    for action, color in zip(['allow', 'challenge', 'reject'], ['green', 'orange', 'red']):
        action_scores = [score for score, act in zip(normalized_scores, actions) if act.lower() == action]
        if action_scores:
            plt.hist(action_scores, alpha=0.5, label=action, color=color, bins=15)
    
    # 绘制阈值线
    plt.axvline(x=lower_threshold, color='blue', linestyle='--', label=f'低/中阈值: {lower_threshold:.3f}')
    plt.axvline(x=upper_threshold, color='purple', linestyle='--', label=f'中/高阈值: {upper_threshold:.3f}')
    
    plt.title('风险分数分布与阈值')
    plt.xlabel('归一化风险分数')
    plt.ylabel('频率')
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    # 保存图表
    plt.savefig(os.path.join(output_dir, 'risk_distribution.png'))
    plt.close()

def main():
    # 直接使用sample_risk_data.csv作为输入文件
    input_file = os.path.join(os.path.dirname(__file__), 'sample_risk_data.csv')
    
    # 检查文件是否存在
    if not os.path.exists(input_file):
        print(f"错误：文件 {input_file} 不存在")
        return
    
    # 读取CSV文件
    try:
        df = pd.read_csv(input_file)
        print(f"成功读取文件，共 {len(df)} 行数据")
    except Exception as e:
        print(f"读取文件时出错: {e}")
        return
    
    # 检查必要的列是否存在
    if 'scores' not in df.columns or 'action' not in df.columns:
        print("错误：CSV文件必须包含'scores'和'action'列")
        return
    
    # 对scores列进行归一化
    normalized_scores = min_max_normalize(df['scores'].tolist())
    df['normalized_score'] = normalized_scores
    
    # 确定阈值
    lower_threshold, upper_threshold = determine_thresholds(normalized_scores, df['action'].tolist())
    print(f"\n计算得出的阈值:")
    print(f"低/中风险阈值: {lower_threshold:.4f}")
    print(f"中/高风险阈值: {upper_threshold:.4f}")
    
    # 根据阈值分配风险等级
    df['risk_level'] = df['normalized_score'].apply(lambda x: assign_risk_level(x, lower_threshold, upper_threshold))
    
    # 创建输出目录（与脚本文件相同目录）
    output_dir = os.path.dirname(__file__)
    
    # 绘制分布图
    plot_distribution(normalized_scores, df['action'].tolist(), lower_threshold, upper_threshold, output_dir)
    
    # 保存结果到新的CSV文件
    output_file = os.path.join(output_dir, 'normalized_risk_data.csv')
    df.to_csv(output_file, index=False)
    print(f"\n结果已保存到: {output_file}")
    print(f"分布图已保存到: {os.path.join(output_dir, 'risk_distribution.png')}")

if __name__ == "__main__":
    main()