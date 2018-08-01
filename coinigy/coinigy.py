from collections import namedtuple
import configparser
import datetime
import logging
from pprint import pprint
import sys
import time

import hmac
import hashlib

import dateparser
import numpy as np
import pandas as pd
import requests
from requests.auth import AuthBase

#logging.basicConfig()
logger = logging.getLogger(__name__)
#logger.setLevel(logging.DEBUG)

credentials = namedtuple('credentials', ('api', 'secret', 'endpoint'))
connection = namedtuple('connection', ('hostname', 'port', 'secure'))
alerts = namedtuple('alerts', ('open_alerts', 'alert_history'))


class CoinigyAuth(AuthBase):

    def __init__(self, api, secret):
        self.coinigy_api = api
        self.coinigy_secret = secret


    def __call__(self, request):
        x_api_timestamp = str(int(time.time()))
        logger.debug('x_api_timestamp: ' + x_api_timestamp)

        method = request.method
        logger.debug('method: ' + method)

        resource_path = request.path_url
        if '?' in resource_path:
            resource_path = resource_path.split('?')[0]
        logger.debug('resource_path: ' + resource_path)

        body = (request.body or '')
        logger.debug('body: ' + body)

        message = self.coinigy_api + x_api_timestamp + method + resource_path + body
        logger.debug('message: ' + message)

        signature_hex = hmac.new(self.coinigy_secret.encode('ascii'), message.encode('ascii'), digestmod=hashlib.sha256).hexdigest()#.digest()
        #signature_hex = map("{:02X}".format, signature_bytes)
        x_api_sign = ''.join(signature_hex)

        request.headers.update({
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-API-SIGN': x_api_sign,
            'X-API-TIMESTAMP': x_api_timestamp,
            'X-API-KEY': self.coinigy_api
        })

        return request


class CoinigyV2:

    def __init__(self, api, secret):
        self.coinigy_api = api
        self.coinigy_secret = secret

        self.coinigy_auth = CoinigyAuth(api, secret)

        self.url_base = 'https://api.coinigy.com/api/v2'


    def request(self, method, resource, params={}, data={}):
        url_request = self.url_base + resource
        logger.debug('url_request: ' + url_request)

        if method.upper() == 'GET':
            r = requests.get(url_request, auth=self.coinigy_auth, params=params, data=data)
        elif method.upper() == 'POST':
            r = requests.post(url_request, auth=self.coinigy_auth, params=params, data=data)

        logger.debug('r.status_code: ' + str(r.status_code))
        logger.debug('r.reason: ' + str(r.reason))

        if r.status_code == 200:
            json_data = r.json()

            if json_data['success'] == True:
                return_data = json_data['result']
            else:
                return_data = json_data['error']
                logger.error('Error returned from API request.')
        else:
            logger.error('HTTP error code returned from API request.')
            return_data = None

        return return_data


    def exchanges(self):
        return self.request(method='GET', resource='/private/exchanges')


    def candles(self, exchange, base_currency, quote_currency, interval, start=None, end=None, start_str=None, limit=None):
        """
        exchange: ex. GDAX
        base_currency: ex. LTC
        quote_currency: ex. BTC
        interval: ex. 60 (integer value representing minutes)
        start: ex. 2018-07-31T22:59:59Z (ISO UTC Datetime)
        end: ex. 2018-07-31T22:59:59Z (ISO UTC Datetime)
        start_str: ex. 48 hours ago UTC
        limit: ex. 48 (Limit return data to X most recent candles)
        """
        resource = '/private/exchanges/' + exchange + '/markets/' + base_currency + '/' + quote_currency + '/ohlc/' + interval
        logger.debug('resource: ' + resource)

        if start_str != None:
            start = dateparser.parse(start_str).isoformat(timespec='seconds').split('+')[0] + 'Z'

        if end == None:
            end = datetime.datetime.utcnow().isoformat(timespec='seconds').split('+')[0] + 'Z'

        logger.debug('exchange: ' + exchange)
        logger.debug('base_currency: ' + base_currency)
        logger.debug('quote_currency: ' + quote_currency)
        logger.debug('interval: ' + interval)
        logger.debug('start: ' + start)
        logger.debug('end: ' + end)

        params = {
            'StartDate': start,
            'EndDate': end
        }
        logger.debug('params: ' + str(params))

        return_data = self.request(method='GET', resource=resource, params=params)

        if limit != None and len(return_data) > limit:
            return_data = return_data[(-1 * limit):]

        return return_data


class Coinigy:
    """
        This class implements Coinigy's REST API as documented in the documentation
        available at
        https://github.com/coinigy/api
    """
    def __init__(self, acct):
        self.api = acct.api
        self.secret = acct.secret
        self.endpoint = acct.endpoint


    def request(self, method, query=None, json_output=False, **args):
        """
        Generic interface to REST API
        :param method:  query name
        :param query:   dictionary of inputs
        :param json:    if True return the raw results in json format
        :param args:    keyword arguments added to the payload
        :return:
        """
        url = '{endpoint}/{method}'.format(endpoint=self.endpoint, method=method)

        authAPI = {'X-API-KEY': self.api, 'X-API-SECRET': self.secret}

        payload = {}

        payload.update(**args)

        if query is not None:
            payload.update(query)

        try:
            r = requests.post(url, data=payload, headers=authAPI)

            if 'error' in r.json().keys():
                print(r.json()['error'])

                return

            if json_output:
                return r.json()

            return pd.DataFrame(r.json()['data'])

        #except json.decoder.JSONDecodeError as e:
            #logger.error('json.decoder.JSONDecodeError while requesting data.')
            #logger.error(e)

            #return -1

        #except json.JSONDecodeError as e:
            #logger.error('json.JSONDecodeError while requesting data.')
            #logger.error(e)

            #return -2

        except Exception as e:
            logger.exception('Exception while requesting data.')
            logger.exception(e)

            #return -3
            return -1


    def data(self, exchange, market, data_type):
        """
        Common wrapper for data related queries
        :param exchange:
        :param market:
        :param data_type: currently supported are 'history', 'bids', 'asks', 'orders'
        :return:
        """
        d = self.request('data', exchange_code=exchange, exchange_market=market, type=data_type, json_output=True)['data']

        res = dict()

        for key in ['history', 'bids', 'asks']:
            if key in d.keys():
                dat = pd.DataFrame.from_records(d[key])
                if 'price' in dat.columns:
                    dat.price = dat.price.astype(np.float)

                if 'quantity' in dat.columns:
                    dat.quantity = dat.quantity.astype(np.float)

                if 'total' in dat.columns:
                    dat.total = dat.total.astype(np.float)

                if 'time_local' in dat.columns:
                    dat.time_local = pd.to_datetime(dat.time_local, format='%Y-%m-%d %H:%M:%S')

                    dat.set_index('time_local', inplace=True)

                if 'type' in dat.columns:
                    dat.type = dat.type.astype(str)

                if not dat.empty:
                    dat['base_ccy'] = d['primary_curr_code']

                    dat['counter_ccy'] = d['secondary_curr_code']

                res[key] = dat

        return res


    def exchanges(self, json_output=True):
        return self.request('exchanges', json_output=json_output)


    def markets(self, exchange, json_output=True):
        return self.request('markets', exchange_code=exchange, json_output=json_output)


    def news_feed(self):
        dat = self.request('newsFeed')

        dat.timestamp = pd.to_datetime(dat.timestamp)

        dat.set_index('timestamp', inplace=True)

        return dat


    def push_notifications(self):
        return self.request('pushNotifications')


    def alerts(self):
        all_alerts = self.request('alerts', json_output=True)['data']

        open_alerts = pd.DataFrame(all_alerts['open_alerts'])

        alert_history = pd.DataFrame(all_alerts['alert_history'])

        return alerts(open_alerts=open_alerts, alert_history=alert_history)


    def favorites(self, json_output=True):
        return self.request('userWatchList', json_output=json_output)


    def accounts(self, json_output=True):
        return self.request('accounts', json_output=json_output)


    def activity(self, json_output=True):
        return self.request('activity', json_output=json_output)


    def balances(self, json_output=True):
        return self.request('balances', json_output=json_output)


    def refresh_balance(self):
        return self.request('refreshBalance', json_output=True)


    def history(self, exchange, market, json_output=True):
        return self.data(exchange=exchange, market=market, data_type='history', json_output=json_output)['history']


    def asks(self, exchange, market, json_output=True):
        return self.data(exchange=exchange, market=market, data_type='asks', json_output=json_output)['asks']


    def bids(self, exchange, market, json_output=True):
        return self.data(exchange=exchange, market=market, data_type='bids', json_output=json_output)['bids']


    def orders(self, exchange, market, json_output=True):
        return self.data(exchange=exchange, market=market, data_type='orders', json_output=json_output)


    def balance_history(self, date):
        '''
        NB: the timestamp columns is the time when the account was last snapshot, not the time the balances were
            effectively refreshed
        :param date:    date str in format YYYY-MM-DD
        :return:        a view of the acccount balances as of the date provided
        '''
        bh = pd.DataFrame.from_records(self.request('balanceHistory', date=date, json_output=True)['data']['balance_history'])

        if bh.empty:
            return bh

        acct = self.accounts()[['auth_id', 'exch_name']]

        return pd.merge(bh, acct, on='auth_id', how='left')


    def add_alert(self, exchange, market, price, note):
        return self.request('addAlert',
                            exch_code=exchange,
                            market_name=market,
                            alert_price=price,
                            alert_note=note,
                            json_output=True)['notifications']

    def delete_alert(self, alert_id):
        return self.request('deleteAlert', alert_id=alert_id, json_output=True)['notifications']


    """
    def open_orders(self):
        '''
            FIXME: untested
        '''
        return self.request('orders', json_output=True)


    def order_types(self):
        dat = self.request('orderTypes', json_output=True)['data']
        return dict(order_types=pd.DataFrame.from_records(dat['order_types']),
                    price_types=pd.DataFrame.from_records(dat['price_types']))


    def add_order(self, auth_id, exch_id, mkt_id, order_type_id, price_type_id, limit_price, stop_price, order_quantity):
        '''
        FIXME: untested
        '''
        return self.request('addOrder',
                            auth_id = auth_id,
                            exch_id=exch_id,
                            mkt_id=mkt_id,
                            order_type_id=order_type_id,
                            price_type_id=price_type_id,
                            limit_price=limit_price,
                            stop_price=stop_price,
                            order_quantity=order_quantity,
                            json_output=True)


    def cancel_order(self, order_id):
        return self.request('cancelOrder', internal_order_id=order_id, json_output=True)
    """


if __name__ == '__main__':
    config_path = '../../cryptocoinalerts/config/config.ini'

    config = configparser.ConfigParser()
    config.read(config_path)

    # Coinigy API v2
    coinigy_api = config['coinigy']['api']
    coinigy_secret = config['coinigy']['secret']

    coinigy_client = CoinigyV2(coinigy_api, coinigy_secret)

    candles = coinigy_client.candles(exchange='GDAX', base_currency='LTC', quote_currency='BTC', interval='60', start_str='48 hours ago UTC', limit=48)#, end=end_time)

    print('Candles:')
    pprint(candles)
    print(len(candles))

    """
    # Coinigy API v1
    credentials.api = config['coinigy']['api']
    credentials.secret = config['coinigy']['secret']
    credentials.endpoint = config['coinigy']['url']

    cr = Coinigy(credentials)

    favorites = cr.favorites()

    print('Favorites:')
    pprint(favorites)

    gdax_markets = cr.markets('GDAX')

    print('GDAX Markets:')
    pprint(gdax_markets)\
    """
