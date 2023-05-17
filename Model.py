# 모델 생성 후 저장

from elasticsearch import Elasticsearch
from elasticsearch import RequestsHttpConnection
from elasticsearch.helpers import scan
from pycaret.anomaly import *
import pandas as pd
import datetime
import warnings
warnings.filterwarnings("ignore")



# Elasticsearch 접속
es = Elasticsearch(['https://localhost:9200'], connection_class=RequestsHttpConnection, use_ssl=True, verify_certs=False, http_auth=('ID', 'PW'), timeout=300)

# 어제
now = datetime.datetime.now()
one_day_ago = now - datetime.timedelta(days=1)
formatted_date = one_day_ago.strftime("%Y%m%d")

# 전날 데이터로 학습
index_es = "syslog_fw_" + formatted_date
index = [index_es]

# 사용하지 않는 도큐먼트 제외
body = {
    "query": {
        "bool": {
            "must_not": {
                "term": {"host": ""}
            }
        }
    }
}

# 엘라스틱서치에서 지정된 파라미터에 맞는 검색 결과 results에 저장
results = scan(es, index=index, query=body)

# 결과를 리스트에 지정한 형태로 저장
result_list = []

# 필드 검색
fields= ["dst_ip", "src_ip", "dst_port", "src_port", "stime", "proto", 'r_pkts', 's_pkts', 'device','action', '@timestamp']

# 검색 결과 처리
for result in results:
    fields_dict = {}
    for field in fields:
        try:
            fields_dict[field] = result["_source"].get(field, None)
            # 실행할 코드
        except:
            continue

    result_list.append(fields_dict)

    #if len(result_list) % 100000 == 0:
    #    print(fields_dict)
    #    print(len(result_list))

    # 몇개의 도큐먼트 가져올지
    if len(result_list) >= 5000000:
        break


# 데이터 프레임 변환
train = pd.DataFrame(result_list)

# null값 drop
train.dropna()

# pycaret iforest 학습
s = setup(train,
          normalize=True,                # 데이터 정규화
          session_id=123)                # 시드(SEED) 지정

# isolation forest 모델 생성
iforest = create_model('iforest')
save_model(iforest, 'detect_model')
