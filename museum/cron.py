from .models import *
import datetime
import pytz
#def my_scheduled_job():
#    start_datetime=datetime.datetime.now()-datetime.timedelta(2)
#    end_datetime=datetime.datetime.now()
#    date1=datetime.datetime(start_datetime.year,start_datetime.month,start_datetime.day,0,0,0,0,tzinfo=pytz.UTC)
#    print(date1)
#    date2=datetime.datetime(end_datetime.year,end_datetime.month,end_datetime.day,0,0,0,0,tzinfo=pytz.UTC)
#    print(date2)
#    for i in range (((date2-date1).days)+1):
#        date3=date1+datetime.timedelta(i)
#        date4=date3+datetime.timedelta(1)
#        if Holiday.objects.filter(holiday=date3).exists():
#            pass
#        else:
#            nodeO=Node.objects.filter(is_config=True).exclude(category__in=['PROJECTOR','PROJECTOR_B15'])
#            for j in nodeO:
#                heartbeat_count=NodeLog.objects.filter(node=j,created_at__range=(date3,date4)).count()
#                print(heartbeat_count)
#                if heartbeat_count >= 240:
#                    reportO=Report.objects.create(node=j,online_percentage=100,report_date=date3)
#                    reportO.save()
#                else:
#                    reportO=Report.objects.create(node=j,online_percentage=(100*heartbeat_count)/240,report_date=date3)
#                    reportO.save()


def my_scheduled_job():
     today_datetime=datetime.datetime.now()
     tomorrow_datetime=datetime.datetime.now()+datetime.timedelta(1)
     today_date=datetime.datetime(today_datetime.year,today_datetime.month,today_datetime.day,0,0,0,0,tzinfo=pytz.UTC)
     tomorrow_date=datetime.datetime(tomorrow_datetime.year,tomorrow_datetime.month,tomorrow_datetime.day,0,0,0,0,tzinfo=pytz.UTC)
     if Holiday.objects.filter(holiday=today_date).exists():
         pass
     else:
         nodeO=Node.objects.filter(is_config=True).exclude(category__in=['PROJECTOR','PROJECTOR_B15'])
         for j in nodeO:
             heartbeat_count=NodeLog.objects.filter(node=j,created_at__range=(today_date,tomorrow_date)).count()
             print(heartbeat_count)
             if heartbeat_count >= 240:
                 reportO=Report.objects.create(node=j,online_percentage=100,report_date=today_date,downtime=0)
                 reportO.save()
             else:
                #total number of heartbeats per minute =6, therefore downtime=8(operational hours in museum)-(heartbeat_count/30(total number of heartbeats in an hour))
                 reportO=Report.objects.create(node=j,online_percentage=(100*heartbeat_count)/240,report_date=today_date,downtime=8-(heartbeat_count/30))
                 reportO.save()
                     

