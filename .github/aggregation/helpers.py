def time_convert(date_str, dt_format):
    '''
    Helper function to convert current timestamps into the ICSA format "%Y-%m-%dT%H:%M:%S.%fZ"
    '''
    converted = ''
    if not ("T" in date_str) and not ("Z" in date_str):
        try:
            datetime_str = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        except:
            datetime_str = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S.%f")
        datetime_str = datetime_str.astimezone(timezone('UTC'))
        converted = datetime_str.strftime(dt_format)
    elif not ("Z" in date_str):
        # Check if milliseconds is too long
        if "+" in date_str and "." in date_str:
            dater = date_str.split(".")[0] 
            temp = date_str.split(".")[1]
            utcer = temp.split("+")[1]
            temp = temp.split("+")[0]
            temp = temp[:6]
            date_str = dater + "." + temp + "+" + utcer
        try:
            datetime_str = datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S%z")
        except:
            datetime_str = datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f%z")
        datetime_str = datetime_str.astimezone(timezone('UTC'))
        converted = datetime_str.strftime(dt_format)
    else: #Essentially skipping ones already correct
        try:
            datetime_str = datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        except:
            datetime_str = datetime.datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
        #datetime_str = datetime_str.astimezone(timezone('UTC'))
        converted = datetime_str.strftime(dt_format)

    return converted