from datetime import datetime


def get_time_now():
    return datetime.now().strftime("%d-%m-%Y %H:%M:%S")