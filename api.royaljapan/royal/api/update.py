from apscheduler.schedulers.background import BackgroundScheduler

from royal.api.models import User
from django.db.models import Q
from datetime import datetime
from dateutil.relativedelta import relativedelta


scheduler = BackgroundScheduler()

job = None

def update():
    now = datetime.utcnow()
    later = now + relativedelta(days=+30)
    # print(later)
    # users = User.objects.filter((Q(userstatus=2) | Q(userstatus=3)))
    # for user in users:
    #     if user.expirydate!=None:
    #         print(user.expirydate)
    #     else:
    #         print(user)

def start():
    global job
    job = scheduler.add_job(update, 'interval', seconds=1)
    try:
        scheduler.start()
    except:
        pass