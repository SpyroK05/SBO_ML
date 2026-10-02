"""Generate a standalone Kaggle notebook from the checked-in training sources."""
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    bundled = {f'training/{p.name}': p.read_text(encoding='utf-8')
               for p in sorted((root / 'training').glob('*.py')) if p.name != Path(__file__).name}
    bundled['requirements-training.txt'] = (root / 'requirements-training.txt').read_text(encoding='utf-8')
    cells = []
    def md(text):
        cells.append({'cell_type': 'markdown', 'metadata': {}, 'source': text.splitlines(True)})
    def code(text, hidden=False):
        cells.append({'cell_type': 'code', 'execution_count': None,
                      'metadata': {'jupyter': {'source_hidden': hidden}} if hidden else {},
                      'outputs': [], 'source': text.splitlines(True)})
    md('''# SBO ML — Kaggle training

Notebook độc lập: mã trong `training/` đã được nhúng vào cell khởi tạo. Chỉ cần cung cấp CSV gốc
`dataset_labeled_sbo_rich_v6_context_clean.csv` (hoặc tar.gz chứa file này) qua dữ liệu đầu vào Kaggle.
Không dùng CSV 200 dòng của demo để báo cáo chất lượng.

Luồng mới tách nhóm train/meta/select/test **trước** khi chọn đặc trưng. Feature ranking, audit và
chọn 160/260 feature chỉ nhìn tập train; các bước tune threshold/ensemble dùng validation.
Số liệu mới sẽ khác log cũ và chưa được tạo sẵn trong notebook này.
''')
    code('''from pathlib import Path
import sys, json, shutil, tarfile, subprocess, importlib.metadata, zipfile
from datetime import datetime, timezone
from uuid import uuid4

INPUT_ROOT = Path('/kaggle/input')
WORK = Path('/kaggle/working/SBO_ML') / (datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S') + '_' + uuid4().hex[:6])
WORK.mkdir(parents=True, exist_ok=False)
FEATURE_COUNT = 260  # 260 hoặc 160; dùng validation để quyết định giữa các cấu hình.
N_JOBS = 4
SEED = 42
CSV_NAME = 'dataset_labeled_sbo_rich_v6_context_clean.csv'
INPUT_FILE = None  # Điền Path('/kaggle/input/.../file.csv') nếu có nhiều bộ dữ liệu.
print('Output directory:', WORK)
''')
    md('## Khởi tạo mã nguồn\nCell dưới được sinh từ mã trong repository; không chứa log hoặc kết quả train cũ.\n')
    code('BUNDLED_SOURCES = ' + repr(bundled) + '''
for relative, content in BUNDLED_SOURCES.items():
    path = WORK / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')
print('Prepared', len(BUNDLED_SOURCES), 'source/configuration files')
''', hidden=True)
    code('''INSTALL_DEPENDENCIES = False  # Bật nếu cần; việc tải package cần Internet.
if INSTALL_DEPENDENCIES:
    subprocess.run([sys.executable, '-m', 'pip', 'install', '-r', str(WORK / 'requirements-training.txt')], check=True)
for package in ['pandas', 'numpy', 'scikit-learn', 'xgboost', 'joblib', 'matplotlib']:
    print(package, importlib.metadata.version(package))
# Nếu vừa đổi phiên bản thư viện đã import trong kernel, khởi động lại session trước khi train.
''')
    code('''DATA_CSV = WORK / CSV_NAME
if INPUT_FILE is not None:
    candidates = [Path(INPUT_FILE)]
else:
    candidates = sorted(INPUT_ROOT.rglob(CSV_NAME))
if len(candidates) > 1:
    raise ValueError('Có nhiều CSV; đặt INPUT_FILE để chọn rõ dữ liệu.')
if candidates:
    shutil.copyfile(candidates[0], DATA_CSV)
else:
    archives = sorted(INPUT_ROOT.rglob('*.tar.gz'))
    matches = []
    for archive in archives:
        with tarfile.open(archive, 'r:gz') as handle:
            matches.extend((archive, member.name) for member in handle.getmembers()
                           if member.isfile() and Path(member.name).name == CSV_NAME)
    if len(matches) != 1:
        raise ValueError(f'Cần đúng một CSV trong input hoặc archive; tìm thấy {len(matches)}.')
    archive, member_name = matches[0]
    with tarfile.open(archive, 'r:gz') as handle:
        with handle.extractfile(member_name) as source, DATA_CSV.open('wb') as destination:
            shutil.copyfileobj(source, destination)
print('Input:', DATA_CSV, 'bytes:', DATA_CSV.stat().st_size)
''')
    md('''## Huấn luyện

Cell này chạy selector RF/ExtraTrees, mutual information, correlation pruning, rồi bốn model cơ sở
và ensemble. CPU và tìm trọng số có thể tốn nhiều thời gian. Đây không phải cell kiểm tra nhanh.
Đặt `PREPARE_ONLY=True` để chỉ kiểm tra cách chia nhóm; chưa train hoặc chọn feature.
''')
    code('''PREPARE_ONLY = False
RUN_DIR = WORK / ('experiment_' + uuid4().hex[:8])
command = [sys.executable, str(WORK / 'training/run_experiment.py'),
           '--data', str(DATA_CSV), '--out-dir', str(RUN_DIR),
           '--features', str(FEATURE_COUNT), '--n-jobs', str(N_JOBS), '--seed', str(SEED)]
if PREPARE_ONLY:
    command.append('--prepare-only')
with (WORK / 'training.log').open('w', encoding='utf-8') as log:
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, bufsize=1) as process:
        for line in process.stdout:
            print(line, end='')
            log.write(line)
        returncode = process.wait()
    if returncode:
        raise RuntimeError(f'Training failed with exit code {returncode}; inspect training.log')
''')
    code('''import pandas as pd
metrics_file = RUN_DIR / 'models/model_metrics.csv'
if metrics_file.exists():
    display(pd.read_csv(metrics_file))
else:
    print('Chưa có metrics; PREPARE_ONLY chỉ tạo split manifest.')
''')
    md('''## Xuất kết quả

ZIP chứa model, schema, metrics, tham số, phiên bản thư viện và split manifest. Dữ liệu đầy đủ và
test_predictions.csv không được đưa vào ZIP này. Model train 160 feature cần CSV/schema 160 tương ứng;
không thay riêng model vào bundle demo 260 feature.

Tập test vẫn có thể bị dùng gián tiếp nếu liên tục chọn cấu hình theo kết quả của nó. Hãy quyết định
thiết kế bằng validation và có thêm tập kiểm chứng cuối từ chương trình/nhóm mẫu chưa dùng.
''')
    code('''ARCHIVE = WORK / 'SBO_training_artifacts.zip'
with zipfile.ZipFile(ARCHIVE, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
    for file in (RUN_DIR / 'models').glob('*'):
        if file.is_file() and file.name != 'test_predictions.csv':
            archive.write(file, 'models/sbo_detector/' + file.name)
    for filename in ['split_manifest.json', 'source_split_manifest.json']:
        file = RUN_DIR / filename
        if file.exists():
            archive.write(file, filename)
    archive.write(WORK / 'training.log', 'training.log')
print('Download:', ARCHIVE)
from IPython.display import FileLink
display(FileLink(str(ARCHIVE)))
''')
    output = root / 'notebooks/SBO_Kaggle_Training.ipynb'
    output.parent.mkdir(exist_ok=True)
    notebook = {'cells': cells, 'metadata': {'kernelspec': {'display_name': 'Python 3', 'language': 'python', 'name': 'python3'},
                                           'language_info': {'name': 'python', 'version': '3.11'}},
                'nbformat': 4, 'nbformat_minor': 5}
    for i, cell in enumerate(cells):
        cell['id'] = f'sbo-cell-{i:02d}'
    output.write_text(json.dumps(notebook, ensure_ascii=False, indent=1) + '\n', encoding='utf-8')
    print(output)


if __name__ == '__main__':
    main()
