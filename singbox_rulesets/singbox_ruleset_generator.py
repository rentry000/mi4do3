import os
import gzip
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import math
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context
import subprocess
import shutil
import time
import json
import tempfile

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 配置参数
CONFIG = {
    'base_url': "https://cs1.ip.thc.org/",
    'num_latest_files': 7,
    'num_splits': 10,
    'github_repo_url': "https://github.com/rentry000/mi4do3.git",
    'local_repo_path': "singbox_rulesets",
    'branch': "main",
    'singbox_version': "1.12.0",
    'max_files_per_push': 20,
    'commit_batch_size': 10,
    'push_delay': 5
}

class CustomHTTPAdapter(HTTPAdapter):
    """自定义HTTP适配器解决SSL兼容性问题"""
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context()
        context.options |= 0x4  # OP_LEGACY_SERVER_CONNECT
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

def set_git_defaults():
    """设置Git默认配置"""
    try:
        subprocess.run(['git', 'config', '--global', 'init.defaultBranch', CONFIG['branch']], check=True)
        subprocess.run(['git', 'config', '--global', 'user.name', 'GitHub Actions'], check=True)
        subprocess.run(['git', 'config', '--global', 'user.email', 'actions@github.com'], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Git配置失败: {e}")

def init_github_repo():
    """初始化本地Git仓库"""
    if not os.path.exists(CONFIG['local_repo_path']):
        os.makedirs(CONFIG['local_repo_path'])
    
    git_dir = os.path.join(CONFIG['local_repo_path'], '.git')
    if not os.path.exists(git_dir):
        # 初始化仓库
        subprocess.run(['git', 'init'], cwd=CONFIG['local_repo_path'], check=True)
        
        # 设置远程仓库
        subprocess.run(['git', 'remote', 'add', 'origin', CONFIG['github_repo_url']], 
                      cwd=CONFIG['local_repo_path'], check=True)
        
        # 切换到配置的分支
        subprocess.run(['git', 'checkout', '-b', CONFIG['branch']],
                      cwd=CONFIG['local_repo_path'], check=True)
        
        print(f"已初始化Git仓库: {CONFIG['local_repo_path']}")

def git_push_batches(file_paths):
    """分批提交和推送文件"""
    if not file_paths:
        print("没有需要推送的文件")
        return
        
    # 确保仓库是最新状态
    try:
        subprocess.run(['git', 'pull', '--rebase', 'origin', CONFIG['branch']],
                     cwd=CONFIG['local_repo_path'], check=True)
    except subprocess.CalledProcessError:
        print("首次推送，无需拉取")
    
    # 检查Git状态
    status_result = subprocess.run(['git', 'status', '--porcelain'], 
                                 cwd=CONFIG['local_repo_path'], capture_output=True, text=True)
    print(f"Git状态:\n{status_result.stdout}")

    for i in range(0, len(file_paths), CONFIG['commit_batch_size']):
        batch = file_paths[i:i + CONFIG['commit_batch_size']]
        commit_message = f"Update rulesets (batch {i//CONFIG['commit_batch_size'] + 1})"
        
        try:
            # 添加文件
            for file in batch:
                rel_path = os.path.relpath(file, CONFIG['local_repo_path'])
                subprocess.run(['git', 'add', rel_path], 
                             cwd=CONFIG['local_repo_path'], check=True)
            
            # 检查是否有变更
            status_result = subprocess.run(['git', 'status', '--porcelain'], 
                                        cwd=CONFIG['local_repo_path'], capture_output=True, text=True)
            if not status_result.stdout.strip():
                print("没有需要提交的变更")
                continue
            
            # 提交
            subprocess.run(['git', 'commit', '-m', commit_message],
                         cwd=CONFIG['local_repo_path'], check=True)
            
            # 推送
            push_result = subprocess.run(['git', 'push', 'origin', CONFIG['branch']],
                         cwd=CONFIG['local_repo_path'], capture_output=True, text=True)
            if push_result.returncode != 0:
                print(f"推送失败: {push_result.stderr}")
                # 尝试强制推送
                subprocess.run(['git', 'push', '--force', 'origin', CONFIG['branch']],
                             cwd=CONFIG['local_repo_path'], check=True)
                print("强制推送成功")
            
            print(f"成功推送批次 {i//CONFIG['commit_batch_size'] + 1} ({len(batch)} 个文件)")
            
            # 避免速率限制
            if i + CONFIG['commit_batch_size'] < len(file_paths):
                time.sleep(CONFIG['push_delay'])
                
        except subprocess.CalledProcessError as e:
            print(f"Git操作失败: {e}")
            # 尝试拉取最新更改后重试
            subprocess.run(['git', 'pull', '--rebase', 'origin', CONFIG['branch']],
                         cwd=CONFIG['local_repo_path'])
            time.sleep(CONFIG['push_delay'])
            continue

def convert_to_intermediate_json(file_path):
    """将原始数据转换为singbox兼容的中间JSON格式"""
    try:
        # 生成中间JSON文件（使用X-Y格式）
        json_file = f"{os.path.splitext(file_path)[0]}.json"
        
        with open(file_path, 'r') as f:
            lines = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]
        
        # 构建singbox规则集格式
        ruleset = {
            "version": 1,
            "rules": []
        }
        
        for line in lines:
            if line.startswith(('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 
                               'IP-CIDR', 'IP-CIDR6', 'GEOIP')):
                parts = line.split(',', 1)
                if len(parts) == 2:
                    rule_type = parts[0].lower().replace('-', '_')
                    value = parts[1].strip()
                    ruleset["rules"].append({rule_type: [value]})
            elif '/' in line and '.' in line:  # 识别为IP-CIDR
                ruleset["rules"].append({"ip_cidr": [line]})
            else:  # 默认为域名规则
                ruleset["rules"].append({"domain": [line]})
        
        # 写入JSON文件
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(ruleset, f, indent=2)
        
        print(f"已创建中间JSON文件: {json_file}")
        return json_file
        
    except Exception as e:
        print(f"转换过程中发生错误: {type(e).__name__}: {str(e)}")
        return None

def compile_to_srs(json_file):
    """使用sing-box命令将JSON编译为.srs格式"""
    try:
        # 确保sing-box已安装
        if not shutil.which('sing-box'):
            install_singbox()
        
        # 生成最终.srs文件（使用相同的X-Y格式）
        srs_file = f"{os.path.splitext(json_file)[0]}.srs"
        
        # 执行编译命令
        result = subprocess.run([
            'sing-box', 'rule-set', 'compile',
            '--output', srs_file,
            json_file
        ], capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"编译失败: {result.stderr}")
            return None
        
        print(f"已生成.srs文件: {srs_file}")
        return srs_file
        
    except Exception as e:
        print(f"编译过程中发生错误: {type(e).__name__}: {str(e)}")
        return None

def install_singbox():
    """下载并安装sing-box命令行工具"""
    try:
        print("正在安装sing-box...")
        version = CONFIG['singbox_version']
        url = f"https://github.com/SagerNet/sing-box/releases/download/v{version}/sing-box-{version}-linux-amd64.tar.gz"
        
        # 创建临时目录
        with tempfile.TemporaryDirectory() as tmpdir:
            # 下载压缩包
            response = requests.get(url, stream=True)
            tar_path = os.path.join(tmpdir, "singbox.tar.gz")
            with open(tar_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # 解压
            shutil.unpack_archive(tar_path, tmpdir)
            
            # 移动二进制文件到PATH
            binary_path = os.path.join(tmpdir, f"sing-box-{version}-linux-amd64", "sing-box")
            target_path = "/usr/local/bin/sing-box"
            shutil.copyfile(binary_path, target_path)
            os.chmod(target_path, 0o755)
            
            print(f"已安装sing-box到 {target_path}")
            
        # 验证安装
        result = subprocess.run(['sing-box', 'version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"sing-box版本: {result.stdout.strip()}")
            return True
            
    except Exception as e:
        print(f"安装sing-box失败: {type(e).__name__}: {str(e)}")
        return False

def download_latest_files():
    """下载最新的文件"""
    try:
        session = requests.Session()
        session.mount('https://', CustomHTTPAdapter())
        session.verify = False
        
        retry_strategy = urllib3.util.Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504]
        )
        session.mount('https://', HTTPAdapter(max_retries=retry_strategy))
        
        print(f"正在访问目录: {CONFIG['base_url']}")
        response = session.get(CONFIG['base_url'], timeout=(30, 60))
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        files = []
        for link in soup.find_all('a'):
            href = link.get('href')
            if href and href.endswith('.txt.gz'):
                date_str = href.split('.')[0]
                try:
                    date = datetime.strptime(date_str, '%Y-%m-%d')
                    files.append((date, href))
                except ValueError:
                    continue
        
        if not files:
            print("目录中没有找到.gz文件")
            return []
        
        files.sort(reverse=True, key=lambda x: x[0])
        latest_files = [f[1] for f in files[:CONFIG['num_latest_files']]]
        
        downloaded_files = []
        os.makedirs('downloads', exist_ok=True)
        
        for file in latest_files:
            file_url = CONFIG['base_url'] + file if CONFIG['base_url'].endswith('/') else CONFIG['base_url'] + '/' + file
            local_path = os.path.join('downloads', file)
            
            print(f"正在下载 {file}...")
            with session.get(file_url, stream=True, timeout=(30, 120)) as r:
                r.raise_for_status()
                with open(local_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        f.write(chunk)
            downloaded_files.append(local_path)
        
        return downloaded_files
    
    except Exception as e:
        print(f"下载文件失败: {type(e).__name__}: {str(e)}")
        return []

def process_and_split_gz(file_path, file_index):
    """处理.gz文件并分割为多个部分"""
    try:
        with gzip.open(file_path, 'rt') as f:
            content = f.read()
        
        lines = content.split('\n')
        part_size = math.ceil(len(lines) / CONFIG['num_splits'])
        
        output_dir = 'output'
        os.makedirs(output_dir, exist_ok=True)
        
        output_files = []
        for i in range(CONFIG['num_splits']):
            part_lines = lines[i*part_size : (i+1)*part_size]
            # 使用X-Y格式命名 (file_index-part_index)
            output_file = os.path.join(output_dir, f'{file_index}-{i+1}.txt')
            
            with open(output_file, 'w') as f:
                f.write('\n'.join(part_lines))
            
            output_files.append(output_file)
        
        print(f"已分割 {file_path} 为 {CONFIG['num_splits']} 个部分: {file_index}-1 到 {file_index}-{CONFIG['num_splits']}")
        return output_files
    
    except Exception as e:
        print(f"处理文件失败: {type(e).__name__}: {str(e)}")
        return []

def process_files():
    """处理文件并生成规则集"""
    downloaded_files = download_latest_files()
    if not downloaded_files:
        return []
    
    all_srs_files = []
    os.makedirs(os.path.join(CONFIG['local_repo_path'], 'rulesets'), exist_ok=True)
    
    # 为每个原始文件分配索引 (1, 2, 3)
    for idx, gz_file in enumerate(downloaded_files, start=1):
        split_files = process_and_split_gz(gz_file, idx)
        if not split_files:
            continue
            
        for split_file in split_files:
            # 生成中间JSON文件
            json_file = convert_to_intermediate_json(split_file)
            if not json_file:
                print(f"无法生成中间JSON文件: {split_file}")
                continue
                
            # 编译为.srs格式
            srs_file = compile_to_srs(json_file)
            
            # 清理中间文件
            if os.path.exists(split_file):
                os.remove(split_file)
            if os.path.exists(json_file):
                os.remove(json_file)
            print(f"已清理中间文件: {split_file} 和 {json_file}")
            
            if srs_file:
                # 保持X-Y命名格式
                base_name = os.path.basename(srs_file)
                dest = os.path.join(CONFIG['local_repo_path'], 'rulesets', base_name)
                shutil.move(srs_file, dest)
                all_srs_files.append(dest)
    
    # 清理下载的原始.gz文件
    for gz_file in downloaded_files:
        if os.path.exists(gz_file):
            os.remove(gz_file)
    print("已清理下载的原始文件")
    
    return all_srs_files

def main():
    print("""
    ========================================
    singbox ruleset 生成与自动上传工具
    ========================================
    """)
    
    # 设置Git默认配置
    set_git_defaults()
    
    # 初始化Git仓库
    init_github_repo()
    
    # 处理文件并生成规则集
    srs_files = process_files()
    
    if srs_files:
        print(f"\n总共生成 {len(srs_files)} 个.srs文件")
        print("文件列表:")
        for file in srs_files:
            print(f"  - {os.path.basename(file)}")
            
        if len(srs_files) > CONFIG['max_files_per_push']:
            print(f"文件数量超过单次推送限制({CONFIG['max_files_per_push']})，将分批推送")
        git_push_batches(srs_files)
    
    print("\n处理完成!")

if __name__ == '__main__':
    main()
