# 저장된 모델 로드 후 인덱스 접근 후 예측

from elasticsearch import Elasticsearch
from elasticsearch import RequestsHttpConnection
from elasticsearch.helpers import scan
from pycaret.anomaly import *
import pandas as pd
import datetime
import warnings
warnings.filterwarnings("ignore")

def log_data(row):
    doc = row.to_dict()
    return doc

# Elasticsearch 접속
es = Elasticsearch(['https://localhost:9200'], connection_class=RequestsHttpConnection, use_ssl=True, verify_certs=False, http_auth=('ID', 'PW'), timeout=300)

# 어제
now = datetime.datetime.now()
one_day_ago = now - datetime.timedelta(days=1)
formatted_date = one_day_ago.strftime("%Y%m%d")


# 오늘 데이터로 예측
index_es = "syslog_fw_" + now
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

    # 몇개의 도큐먼트 가져올지
    if len(result_list) >= 830000:
        break


# 데이터 프레임 변환
result_list = pd.DataFrame(result_list)
test = result_list[["dst_ip", "src_ip", "dst_port", "src_port", "stime", "proto", 'r_pkts', 's_pkts', 'device','action', '@timestamp']]
test = test.dropna()


# 저장된 감지 모델 로드
iforest = load_model('detect_model')


# 이상탐지
predicitons = predict_model(iforest, data=test)
predicitons = pd.DataFrame(predicitons)


# 결과값 device, action 추가
result = predicitons
result['device'] = result_list['device']
result['action'] = result_list['action']
result['@timestamp'] = result_list['@timestamp']


# 결과값 Anomaly 추가
anomalies = result[result['Anomaly'] == 1]


# ano.csv 파일로 이상치 탐지 데이터 저장
#result_list.to_csv("./result.csv")
anomalies.to_csv("./ano.csv")


# stime 열만 추출
#stime_values = result_list['stime']


# 오늘
now = datetime.datetime.now()
formatted_date = now.strftime("%Y%m%d")

# stime을 엘라스틱서치에서 특정 인덱스의 date 필드로 사용하도록 매핑
mapping = {
  "mappings": {
    "properties": {
      "stime": {
        "type": "date",
        "format": "yyyy-MM-dd HH:mm:ss"
      }
    }
  }
}

# 오늘 날짜 인덱스 있는 지 확인, 없으면 인덱스 생성
index_name = "syslog_fw_threat_" + formatted_date
if not es.indices.exists(index_name):
    es.indices.create(index=index_name, body=mapping)

# 이상치 탐지 결과인 anomalies를 도큐먼트로 엘라스틱서치에 저장
for index, row in anomalies.iterrows():
    doc = log_data(row)
    res = es.index(index=index_name, body=doc)

