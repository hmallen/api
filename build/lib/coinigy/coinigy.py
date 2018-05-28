import configparser
from collections import namedtuple
import logging
import numpy as np
import pandas as pd
from pprint import pprint
import requests

logging.basicConfig()
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

credentials = namedtuple('credentials', ('api', 'secret', 'endpoint'))
connection = namedtuple('connection', ('hostname', 'port', 'secure'))
alerts = namedtuple('alerts', ('open_alerts', 'alert_history'))


class CoinigyREST:
    """
        This class implements coinigy's REST api as documented in the documentation
        available at
        https://github.com/coinigy/api
    """
    def __init__(self, acct):
        self.api = acct.api
        self.secret = acct.secret
        self.endpoint = acct.endpoint


    def request(self, method, query=None, json=False, **args):
        """
        Generic interface to REST api
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

        r = requests.post(url, data=payload, headers=authAPI)

        if 'error' in r.json().keys():
            print(r.json()['error'])

            return

        if json:
            return r.json()

        return pd.DataFrame(r.json()['data'])


    def data(self, exchange, market, data_type):
        """
        Common wrapper for data related queries
        :param exchange:
        :param market:
        :param data_type: currently supported are 'history', 'bids', 'asks', 'orders'
        :return:
        """
        d = self.request('data', exchange_code=exchange, exchange_market=market, type=data_type, json=True)['data']

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


    def exchanges(self, json=True):
        return self.request('exchanges', json=json)


    def markets(self, exchange, json=True):
        return self.request('markets', exchange_code=exchange, json=json)


    def news_feed(self):
        dat = self.request('newsFeed')

        dat.timestamp = pd.to_datetime(dat.timestamp)

        dat.set_index('timestamp', inplace=True)

        return dat


    def push_notifications(self):
        return self.request('pushNotifications')


    def alerts(self):
        all_alerts = self.request('alerts', json=True)['data']

        open_alerts = pd.DataFrame(all_alerts['open_alerts'])

        alert_history = pd.DataFrame(all_alerts['alert_history'])

        return alerts(open_alerts=open_alerts, alert_history=alert_history)


    def favorites(self, json=True):
        return self.request('userWatchList', json=json)


    def accounts(self, json=True):
        return self.request('accounts', json=json)


    def activity(self, json=True):
        return self.request('activity', json=json)


    def balances(self, json=True):
        return self.request('balances', json=json)


    def refresh_balance(self):
        return self.request('refreshBalance', json=True)


    def history(self, exchange, market, json=True):
        return self.data(exchange=exchange, market=market, data_type='history', json=json)['history']


    def asks(self, exchange, market, json=True):
        return self.data(exchange=exchange, market=market, data_type='asks', json=json)['asks']


    def bids(self, exchange, market, json=True):
        return self.data(exchange=exchange, market=market, data_type='bids', json=json)['bids']


    def orders(self, exchange, market, json=True):
        return self.data(exchange=exchange, market=market, data_type='orders', json=json)


    def balance_history(self, date):
        '''
        NB: the timestamp columns is the time when the account was last snapshot, not the time the balances were
            effectively refreshed
        :param date:    date str in format YYYY-MM-DD
        :return:        a view of the acccount balances as of the date provided
        '''
        bh = pd.DataFrame.from_records(self.request('balanceHistory', date=date, json=True)['data']['balance_history'])
        if bh.empty:
            return bh
        acct = self.accounts()[['auth_id', 'exch_name']]
        return pd.merge(bh, acct, on='auth_id', how='left')


    """
    def add_alert(self, exchange, market, price, note):
        return self.request('addAlert',
                            exch_code=exchange,
                            market_name=market,
                            alert_price=price,
                            alert_note=note,
                            json=True)['notifications']

    def delete_alert(self, alert_id):
        return self.request('deleteAlert', alert_id=alert_id, json=True)['notifications']


    def open_orders(self):
        '''
            FIXME: untested
        '''
        return self.request('orders', json=True)


    def order_types(self):
        dat = self.request('orderTypes', json=True)['data']
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
                            json=True)


    def cancel_order(self, order_id):
        return self.request('cancelOrder', internal_order_id=order_id, json=True)
    """


if __name__ == "__main__":
    config_path = '../../TeslaBot/config/config.ini'

    config = configparser.ConfigParser()
    config.read(config_path)

    credentials.api = config['coinigy']['api']
    credentials.secret = config['coinigy']['secret']
    credentials.endpoint = config['coinigy']['url']

    cr = CoinigyREST(credentials)

    favorites = cr.favorites()

    print('Favorites:')
    pprint(favorites)

    gdax_markets = cr.markets('GDAX')

    print('GDAX Markets:')
    pprint(gdax_markets)
