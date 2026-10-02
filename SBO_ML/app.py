"""CSV demo for function-level Stack Buffer Overflow risk screening."""
from pathlib import Path
import json

import numpy as np
import pandas as pd
import streamlit as st

from sbo_core import load_bundle, prepare_X, available_models, pick_default_model, predict_from_metrics

ROOT = Path(__file__).resolve().parent
st.set_page_config(page_title='SBO Detector', page_icon='🛡️', layout='wide')
load_models = st.cache_resource(load_bundle)


def main():
    st.title('🛡️ SBO Detector')
    st.caption('Sàng lọc nguy cơ Stack Buffer Overflow theo từng hàm từ 260 đặc trưng tĩnh.')
    st.info('Bản demo nghiên cứu. Cảnh báo cần được kiểm tra lại; kết quả âm tính không chứng minh hàm an toàn.')
    try:
        model_dir, models, metrics, features, errors = load_models(ROOT / 'models/sbo_detector')
        names = available_models(metrics, models)
        default = pick_default_model(metrics, models)
    except Exception as exc:
        st.error(str(exc))
        st.stop()

    with st.sidebar:
        selected = st.selectbox('Model', names, index=names.index(default))
        row = metrics.loc[metrics['model'] == selected].iloc[0]
        threshold = st.slider('Ngưỡng cảnh báo', 0.05, 0.95,
                              float(row['best_threshold']), step=0.005)
        only_flagged = st.checkbox('Chỉ hiện hàm có cảnh báo', value=True)
        st.caption(f'{len(features)} đặc trưng · {len(models)} model cơ sở')
        if errors:
            st.warning('Một số model chưa nạp được; các ensemble phụ thuộc cũng bị ẩn.')
            st.json(errors)

    predict_tab, metric_tab, info_tab = st.tabs(['Dự đoán', 'Kết quả nghiên cứu', 'Thông tin'])
    with predict_tab:
        uploaded = st.file_uploader('CSV đúng schema 260 đặc trưng', type=['csv'])
        sample = ROOT / 'samples/sample_feature_dataset.csv'
        if uploaded is None:
            st.caption('Đang dùng 200 dòng mẫu cân bằng hai lớp để minh họa giao diện.')
        try:
            df = pd.read_csv(uploaded if uploaded is not None else sample)
            X, _ = prepare_X(df, features)
            prob, used, parts, _ = predict_from_metrics(models, metrics, X, selected)
            ids = [c for c in ['binary_norm', 'function', 'entry', 'label'] if c in df.columns]
            result = df[ids].copy()
            result['prob_vulnerable'] = prob
            result['pred_label'] = (prob >= threshold).astype(int)
            result['prediction'] = np.where(result['pred_label'] == 1, 'FLAGGED', 'NOT_FLAGGED')
            result = result.sort_values('prob_vulnerable', ascending=False).reset_index(drop=True)
        except Exception as exc:
            st.error(str(exc))
        else:
            c1, c2 = st.columns(2)
            c1.metric('Số hàm', len(result))
            c2.metric('Có cảnh báo', int(result['pred_label'].sum()))
            st.caption(f'Model: {used} · Thành phần: {parts}')
            view = result[result['pred_label'] == 1] if only_flagged else result
            st.dataframe(view, use_container_width=True, height=500)
            st.download_button('Tải kết quả CSV', result.to_csv(index=False).encode('utf-8'),
                               'sbo_predictions.csv', 'text/csv')

    with metric_tab:
        st.caption('Số liệu từ bản gốc, chưa tái huấn luyện. Stacking/gating chỉ để tham khảo; '
                   'mã train đã bổ sung, chưa kiểm chứng suy luận trong app. Không áp dụng cho điểm luật tĩnh.')
        cols = ['model', 'test_precision_vulnerable', 'test_recall_vulnerable',
                'test_f1_vulnerable', 'test_roc_auc', 'test_fp', 'test_fn']
        st.dataframe(metrics[cols], use_container_width=True)
    with info_tab:
        st.json(json.loads((model_dir / 'run_info.json').read_text(encoding='utf-8')))
        st.dataframe(pd.DataFrame({'feature': features}), use_container_width=True)


if __name__ == '__main__':
    main()
