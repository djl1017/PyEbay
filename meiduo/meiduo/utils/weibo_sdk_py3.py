"""
微博登录mini SDK 说明:

参考官方文档: https://open.weibo.com/wiki/授权机制说明

1. 成为微博开发者, 微博会提供开发者给client_id, clinet_secret (可参考需求文档里已有的, 这步可省略)

2. 让用户登录微博并授权
    官方: https://api.weibo.com/oauth2/authorize?client_id=YOUR_CLIENT_ID&response_type=code&redirect_uri=YOUR_REGISTERED_REDIRECT_URI
    说明:
        a. 需要拼接url, 即将其中的YOUR_CLIENT_ID, YOUR_REGISTERED_REDIRECT_URI 替换成开发者自己的id 和 回调url即可
        b. 返回给前端拼接好的url

        c. 步骤: 实例化 WeiboSDK 类对象, 调用get_weibo_login_url(self ) 返回登录url

3. 换取 access_token:

    官方: https://api.weibo.com/oauth2/access_token?client_id = YOUR_CLIENT_ID & client_secret = YOUR_CLIENT_SECRET & grant_type = authorization_code & redirect_uri = YOUR_REGISTERED_REDIRECT_URI & code = CODE
    说明:
        a. 当用户点击"授权后", 页面自动跳转至 redict_uri(开发者自己的回调页面)/?code=CODE, 即可拿到查询参数code
        b. 换取 access_token 用 code 和开发者的client_id, client_secret 等拼接url
        c. 发 post 请求, 拼接好上述的官方url, 提取响应对象(json)的access_token(用户授权登录的在微博中的唯一标识)

        d. 步骤: 调用  def get_access_token(self, code) 返回该用户的 access_token

"""

import requests
from urllib.parse import urlencode


class WeiboSDK(object):
    """微博登录sdk"""

    def __init__(self, client_id=None, client_secret=None, redirect_uri=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def get_weibo_login_url(self):
        """获取微博登录的url"""
        url_params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
        }

        # 构建认证登录的url
        # "api: https://api.weibo.com/oauth2/authorize?client_id=YOUR_CLIENT_ID&response_type=code&redirect_uri=YOUR_REGISTERED_REDIRECT_URI
        weibo_login_url = 'https://api.weibo.com/oauth2/authorize?' + urlencode(url_params)

        return weibo_login_url

    def get_access_token(self, code):
        """
        :param code:
            a. 用户根据 weibo_longin_url 返回的登录界面, 登录并点击授权后,
            b. 页面跳转至 redirect_uri(自己填写的回调函数)/?code=CODE, 这样就拿到了 code 值

        :return: 用户授权登录后,在微博端生成的唯一标识 access_token
        """
        url_params = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'authorization_code',
            'redirect_uri': self.redirect_uri,
            'code': code
        }

        # 构建获取access_token 的 url
        # https: // api.weibo.com / oauth2 / access_token?client_id = YOUR_CLIENT_ID & client_secret = YOUR_CLIENT_SECRET & grant_type = authorization_code & redirect_uri = YOUR_REGISTERED_REDIRECT_URI & code = CODE
        access_url = 'https://api.weibo.com/oauth2/access_token?' + urlencode(url_params)

        # 发送请求, 注意, 这里的请求必须是post.
        try:
            response = requests.post(access_url)
            '''
            根据官方文档要求发送post请求后, 会放回类似的json数据, access_token的值是唯一的, 可做为用户身份的
            唯一标识.
            {"access_token": "SlAV32hkKG", "expires_in": 3600...}
            '''
            # 提取respons 的 json数据, 类似这样: {'access_token': '2.00342imFJcPibDff97cb67c30JfnWV', 'remind_in': '125879', 'expires_in': 125879,'uid': '5300496892', 'isRealName'}
            json_dict_data = response.json()

        except Exception as e:
            raise e

        # 提取键"access_token"作为用户登录认证的唯一标识即可
        access_token = json_dict_data.get('access_token')

        if access_token is None:
            raise Exception('未获取到 access_token')

        return access_token
