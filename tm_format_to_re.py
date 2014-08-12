import sys
import time
import re

WEEKDAY_EN = '(?u)[Mm][Oo][Nn](?:[Dd][Aa][Yy])?|[Tt][Uu][Ee](?:[Ss]?(?:[Dd][Aa][Yy])?)?|[Ww][Ee][Dd](?:[Nn][Ee][Ss][Dd][Aa][Yy])?|[Tt][Hh][Uu](?:[Rr]?[Ss]?(?:[Dd][Aa][Yy])?)?|[Ff][Rr][Ii](?:[Dd][Aa][Yy])?|[Ss][Aa][Tt](?:[Uu][Rr][Dd][Aa][Yy])?|[Ss][Uu][Nn](?:[Dd][Aa][Yy])?'

MONTH_EN = '(?u)[Jj][Aa][Nn](?:[Uu][Aa][Rr][Yy])?|[Ff][Ee][Bb](?:[Rr][Uu][Aa][Rr][Yy])?|[Mm][Aa][Rr](?:[Cc][Hh])?|[Aa][Pp][Rr](?:[Ii][Ll])?|[Mm][Aa][Yy]|[Jj][Uu][Nn][Ee]?|[Jj][Uu][Ll][Yy]?|[Aa][Uu][Gg](?:[Uu][Ss][Tt])?|[Ss][Ee][Pp](?:[Tt](?:[Ee][Mm][Bb][Ee][Rr])?)?|[Oo][Cc][Tt](?:[Oo][Bb][Ee][Rr])?|[Nn][Oo][Vv](?:[Ee][Mm][Bb][Ee][Rr])?|[Dd][Ee][Cc](?:[Ee][Mm][Bb][Ee][Rr])?'

DAY_MONTH_INT = '[12][0-9]|3[01]|0?[1-9]'

DECIMAL_MONTH_INT = '0[1-9]|[12][0-9]|3[0-1]'

DAY_WEEK_INT = '[0-6]'

TWO_DIGIT_YEAR = '[0-9]{2}'

FOUR_DIGIT_YEAR = '[12]\d'+TWO_DIGIT_YEAR

HOUR_24 = '[01][0-9]|2[0-4]|\d'

HOUR_12 = '0[0-9]|1[0-2]|\d'

DAY_DECIMAL_OF_YEAR = '0?0?\d|0?\d\d|[12]\d\d|3[0-5]\d|36[0-6]'

MONTH_INT = '0[1-9]|1[0-2]'

MINUTE_INT = '[0-5][0-9]'

AMPM = '[AaPp][\.\ ]{0,3}(?:[Mm][\.\ ]{0,3})'

SECOND = '[0-5][0-9]|6[01]'

WEEK_INT = '[0-4][0-9]|5[0-3]'

TIME_ZONE = '[+-]\d\d:?\d\d'

MILLI_SECOND = '\d+'

# reference: https://docs.python.org/2/library/time.html#time.strftime
TIME_FORMAT_TO_RE = {
    "%a":WEEKDAY_EN,
    "%A":WEEKDAY_EN,
    "%b":MONTH_EN,
    "%B":MONTH_EN,
    "%d":DECIMAL_MONTH_INT,
    "%f":MILLI_SECOND,
    '%H':HOUR_24,
    '%I':HOUR_12,
    '%j':DAY_DECIMAL_OF_YEAR,
    '%m':MONTH_INT,
    '%M':MINUTE_INT,
    '%p':AMPM,
    '%S':SECOND,
    '%U':WEEK_INT,
    '%w':DAY_WEEK_INT,
    '%W':WEEK_INT,
    '%y':TWO_DIGIT_YEAR,
    '%Y':FOUR_DIGIT_YEAR,
    '%Z':TIME_ZONE
    }


def tm_format_to_re(time_prefix,time_format):
    time_format = time_format.strip()
    time_format = re.sub("([^\w%])",r"\\\g<1>", time_format)
    for f in TIME_FORMAT_TO_RE:
        time_format = time_format.replace(f,"(?:{0})".format(TIME_FORMAT_TO_RE[f]))
    time_format = re.sub("%\d+[A-Za-z]", "\d+", time_format)
    return "(?P<prefix>{0})(?P<time_str>{1})".format(time_prefix,time_format)
