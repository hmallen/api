import configparser
from collections import namedtuple
import logging
import numpy as np
import pandas as pd
from pprint import pprint
import requests

#logging.basicConfig()
logger = logging.getLogger(__name__)
#logger.setLevel(logging.DEBUG)

credentials = namedtuple('credentials', ('api', 'secret', 'endpoint'))
connection = namedtuple('connection', ('hostname', 'port', 'secure'))
alerts = namedtuple('alerts', ('open_alerts', 'alert_history'))


class CoinigyREST:
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

            if json:
                return r.json()

            return pd.DataFrame(r.json()['data'])

        except json.decoder.JSONDecodeError as e:
            logger.error('json.decoder.JSONDecodeError while requesting data.')
            logger.error(e)

            return -1

        except json.JSONDecodeError as e:
            logger.error('json.JSONDecodeError while requesting data.')
            logger.error(e)

            return -2

        except Exception as e:
            logger.exception('Exception while requesting data.')
            logger.exception(e)

            return -3


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
