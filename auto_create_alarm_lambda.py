
import boto3

cw = boto3.client('cloudwatch')
ec2 = boto3.resource('ec2')
region = 'us-east-1'
# SNS Topic
ec2_sns = 'Your Topic'



def lambda_handler(event, context):

    instanceid=event['detail']['instance-id']
    create_alarm(instanceid)
    


def create_alarm(instanceid):
        
        instance_name = get_instance_name(instanceid)
        
        #Create Alarm DiskSpaceUtilization
        for metric in cw.list_metrics(Dimensions=[{'Name': 'InstanceId', 'Value': instanceid}])['Metrics']:
                if metric['MetricName'] == 'DiskSpaceUtilization' :
                      create_alarm_disk(instance_name,instanceid,metric['Dimensions'][2]['Value'] , metric['Dimensions'][0]['Value'])
        
        
 
     # Create Alarm "MemoryUtilization Utilization Less than 20% for 3+ Minutes"
        cw.put_metric_alarm(
        AlarmName="%s %s High MemoryUtilization Utilization Warning" % (instance_name, instanceid),
        AlarmDescription='MemoryUtilization Utilization Less than 20% for 3+ Minutes',
        ActionsEnabled=True,
        AlarmActions=[
            ec2_sns
        ],
        MetricName='MemoryUtilization',
        Namespace='System/Linux',
        Statistic='Average',
        Dimensions=[
            {
                'Name': 'InstanceId',
                'Value': instanceid
            },
        ],
        Period=300,
        EvaluationPeriods=3,# tempo em minutos
        Threshold=20,
        ComparisonOperator='LessThanThreshold'
    )
    


    # Create Alarm "CPU Utilization Greater than 95% for 12+ Minutes"
        cw.put_metric_alarm(
        AlarmName="%s %s High CPU Utilization Critical" % (instance_name, instanceid),
        AlarmDescription='CPU Utilization Greater than 95% for 12+ Minutes',
        ActionsEnabled=True,
        AlarmActions=[
            ec2_sns
        ],
        MetricName='CPUUtilization',
        Namespace='AWS/EC2',
        Statistic='Average',
        Dimensions=[
            {
                'Name': 'InstanceId',
                'Value': instanceid
            },
        ],
        Period=300,
        EvaluationPeriods=12,# tempo em minutos
        Threshold=95.0,
        ComparisonOperator='GreaterThanOrEqualToThreshold'
    )

    # Create Metric "Status Check Failed (System) for 5 Minutes"
        cw.put_metric_alarm(
        AlarmName="%s %s System Check Failed" % (instance_name, instanceid),
        AlarmDescription='Status Check Failed (System) for 5 Minutes',
        ActionsEnabled=True,
        AlarmActions=[
            ec2_sns,
            "arn:aws:automate:%s:ec2:recover" % region
        ],
        MetricName='StatusCheckFailed_System',
        Namespace='AWS/EC2',
        Statistic='Average',
        Dimensions=[
            {
                'Name': 'InstanceId',
                'Value': instanceid
            },
        ],
        Period=60,
        EvaluationPeriods=5,# tempo em minutos
        Threshold=1.0,
        ComparisonOperator='GreaterThanOrEqualToThreshold'
    )

    # Create Alarm "Status Check Failed (Instance) for 20 Minutes"
        cw.put_metric_alarm(
        AlarmName="%s %s Instance Check Failed" % (instance_name, instanceid),
        AlarmDescription='Status Check Failed (Instance) for 20 Minutes',
        ActionsEnabled=True,
        AlarmActions=[
            ec2_sns
        ],
        MetricName='StatusCheckFailed_Instance',
        Namespace='AWS/EC2',
        Statistic='Average',
        Dimensions=[
            {
                'Name': 'InstanceId',
                'Value': instanceid
            },
        ],
        Period=60,
        EvaluationPeriods=20,# tempo em minutos
        Threshold=1.0,
        ComparisonOperator='GreaterThanOrEqualToThreshold'
    )

    #List All Devices of the Instance
        ec2d = boto3.resource('ec2', region_name= region)
        instance = ec2d.Instance(instanceid)
        vol_id = instance.volumes.all()
        devices = instance.block_device_mappings


        
        for v in vol_id:
            dev = [ dev['DeviceName'] for dev in devices if dev['Ebs']['VolumeId'] == v.id ]
        
            #Create Alarm device disk
            create_alarm_disk_dev(instanceid,v,dev)




def get_instance_name(fid):
    # When given an instance ID as str e.g. 'i-1234567', return the instance 'Name' from the name tag.
    ec2 = boto3.resource('ec2')
    ec2instance = ec2.Instance(fid)
    instancename = ''
    for tags in ec2instance.tags:
        if tags["Key"] == 'Name':
            instancename = tags["Value"]
    return instancename

def create_alarm_disk(instance_name,instanceid,disk,mount_path):

        cw.put_metric_alarm(
        AlarmName="High Disk Utilization Warning %s %s  %s %s" % (instance_name, instanceid,disk,mount_path),
        AlarmDescription='Disk Utilization Greater than 70% ',
        ActionsEnabled=True,
        AlarmActions=[
            ec2_sns
        ],
        MetricName='DiskSpaceUtilization',
        Namespace='System/Linux',
        Statistic='Average',
        Dimensions=[
            {
                'Name': 'InstanceId',
                'Value': instanceid
            },
             {
                'Name': 'Filesystem',
                'Value': disk
            },
             {
                'Name': 'MountPath',
                'Value': mount_path
            },
        ],
        Period=60,
        EvaluationPeriods=1,
        Threshold=70,
        ComparisonOperator='GreaterThanThreshold'
    )

def create_alarm_disk_dev(instanceid,v,dev):


        # Create Alarme "Volume Idle Time <= 30 sec (of 5 minutes) for 30 Minutes"

            cw.put_metric_alarm(
            AlarmName="%s %s %s High Volume Activity Warning" % (v.id, instanceid,dev[0]),
            AlarmDescription='Volume Idle Time <= 30 sec (of 5 minutes) for 30 Minutes',
            ActionsEnabled=True,
            AlarmActions=[
                ec2_sns
            ],
            MetricName='VolumeIdleTime',
            Namespace='AWS/EBS',
            Statistic='Average',
            Dimensions=[
                {
                    'Name': 'VolumeId',
                    'Value': v.id
                },
            ],
            Period=300,
            EvaluationPeriods=6, # tempo em minutos
            Threshold=30.0,
            ComparisonOperator='LessThanOrEqualToThreshold'
            )

        # Create Alarm "Volume Idle Time <= 30 sec (of 5 minutes) for 60 Minutes"
            cw.put_metric_alarm(
            AlarmName="%s %s %s High Volume Activity Critical" % (v.id, instanceid,dev[0]),
            AlarmDescription='Volume Idle Time <= 30 sec (of 5 minutes) for 60 Minutes',
            ActionsEnabled=True,
            AlarmActions=[
                ec2_sns
            ],
            MetricName='VolumeIdleTime',
            Namespace='AWS/EBS',
            Statistic='Average',
            Dimensions=[
                {
                    'Name': 'VolumeId',
                    'Value': v.id
                },
            ],
            Period=300,
            EvaluationPeriods=12, # tempo em minutos
            Threshold=30.0,
            ComparisonOperator='LessThanOrEqualToThreshold'
            )
        





    

