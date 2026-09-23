import json
import os
from .models import Pillar

_CACHE = {}

def get_rule_metadata(pillar: Pillar, check_id: str) -> dict:
    service = check_id.split(".")[0].lower()
    
    # Cost rules overrides
    cost_map = {
        "COST.EBS_UNATTACHED": "ec2",
        "COST.GP2_VOLUMES": "ec2",
        "COST.EIP_UNASSOCIATED": "ec2",
        "COST.NAT_GATEWAY_IDLE": "vpc",
        "COST.ALB_IDLE": "elb",
        "COST.DYNAMODB_PROVISIONED": "dynamodb",
        "COST.RDS_IDLE": "rds",
        "COST.S3_MULTIPART_INCOMPLETE": "s3",
        "COST.EC2_IDLE": "ec2",
        "COST.LAMBDA_HIGH_MEMORY": "lambda"
    }
    if check_id in cost_map:
        service = cost_map[check_id]
        
    filename = f"{service}.json"
    
    if filename not in _CACHE:
        path = os.path.join(os.path.dirname(__file__), "catalog", "rules", filename)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                _CACHE[filename] = json.load(f)
        else:
            _CACHE[filename] = {}
            
    return _CACHE[filename].get(check_id, {})
