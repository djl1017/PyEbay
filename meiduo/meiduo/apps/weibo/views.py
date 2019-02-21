from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_jwt.settings import api_settings
from django_redis import get_redis_connection

from meiduo.utils.weibo_sdk_py3 import WeiboSDK
from oauth.utils import generate_save_user_token
from .serializers import WeiboAuthUserSerializer
from meiduo.libs import captcha
from oauth.models import QQAuthUser


class WeiboImageCode(APIView):

    def get(self, request, image_codes):
        # redis_conn = get_redis_connection('verify_codes')
        # flag = redis_conn.get('send_flag_%s' % image_codes)
        # if flag:
        #     return Response({'message': '频繁发送短信'}, status=status.HTTP_400_BAD_REQUEST)
        #
        # # 3.生成短信验证码
        # sms_code = '%06d' % randint(0, 999999)
        # logger.info(sms_code)
        # # 创建redis管道对象
        # pl = redis_conn.pipeline()
        #
        # # 4.把验证码存储到redis中
        # # redis_conn.setex(key, 过期时间, value)
        # # redis_conn.setex('sms_%s' % mobile, constants.SMS_CODE_REDIS_EXPIRES, sms_code)
        # pl.setex('sms_%s' % mobile, constants.SMS_CODE_REDIS_EXPIRES, sms_code)
        # # 4.1 存储此手机号已发送短信标记
        # # redis_conn.setex('send_flag_%s' % mobile, constants.SEND_SMS_CODE_INTERVAL, 1)
        # pl.setex('send_flag_%s' % mobile, constants.SEND_SMS_CODE_INTERVAL, 1)
        #
        # # 执行管道
        # pl.execute()
        #
        # # 5.利用容联云通讯发短信
        # # CCP().send_template_sms(mobile, [sms_code, constants.SMS_CODE_REDIS_EXPIRES // 60], 1)
        # # 触发异步任务(让发短信不要阻塞主线程)
        # # send_sms_code(mobile, sms_code)
        # send_sms_code.delay(mobile, sms_code)
        # # 6.响应
        # return Response({'message': 'ok'})
        pass


class WeiboAuthURLView(APIView):
    """提供微博登录页面网址"""

    def get(self, request):
        "生成微博登录链接"
        # 获取next(从哪去取到login)参数路基
        next = request.query_params.get('next')
        if not next:
            next = '/'

        authoweibo = WeiboSDK(
            client_id='3305669385',
            client_secret='74c7bea69d5fc64f5c3b80c802325276',
            redirect_uri='http://www.meiduo.site:8080/sina_callback.html'

        )

        # 拼接好的登录链接
        login_url = authoweibo.get_weibo_login_url()

        return Response({'login_url': login_url})


class WeiboAuthUserView(APIView):
    "登录成功后回调处理"

    def get(self, request):
        # 获取查询参数中的code 参数
        code = request.query_params.get('code')
        if not code:
            return Response({'message': "没有code"})

        authoweibo = WeiboSDK(
            client_id='3305669385',
            client_secret='74c7bea69d5fc64f5c3b80c802325276',
            redirect_uri='http://www.meiduo.site:8080/sina_callback.html'

        )

        # 通过code作为获取 access_token的url的参数
        try:
            access_token = authoweibo.get_access_token(code)
            openid=access_token
            print(openid)
        except:
            return Response({'message': '微博服务器异常'})
        # print(access_token)

        try:
            # 查询weibo_token 是否绑定过商城中的用户
            weibo_auth_model = QQAuthUser.objects.get(openid=openid)
        except QQAuthUser.DoesNotExist:
            # 视图一定要有返回值, 之前写的是pass, 就一直没有处理了

            # 将access_token加密后返回给前端, 保存一下
            access_token = generate_save_user_token(openid)
            return Response({'access_token': access_token})

        else:  # 已经绑定过, 则手动生成token
            jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER  # 加载生成载荷函数
            jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER  # 加载生成token函数

            # 获取user对象
            user = weibo_auth_model.user
            payload = jwt_payload_handler(user)  # 生成载荷
            token = jwt_encode_handler(payload)  # 根据载荷生成token

            # print(token)

            response = Response({
                'token': token,
                'username': user.username,
                'user_id': user.id
            })

            # cookie购物车合并到redis
            # merge_cart_cookie_to_redis(request, user, response)

            return response

    def post(self, request):
        """登录post"""

        # 创建序列化器, 进行反序列化
        # 创建序列化器, 进行反序列化, 反序列化, 别忘写 data=request.data
        serializer = WeiboAuthUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # 手动生成jwt token
        # 手动生成jwt Token
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER  # 加载生成载荷函数
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER  # 加载生成token函数

        payload = jwt_payload_handler(user)  # 生成载荷
        token = jwt_encode_handler(payload)  # 根据载荷生成token

        return Response({
            'token': token,
            # 'username': user.username,
            'username': user.username,
            'user_id': user.id
        })


