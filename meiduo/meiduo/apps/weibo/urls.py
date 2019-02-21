from django.conf.urls import url

from . import views

urlpatterns = [
    # 获取微博登录url
    url(r'^weibo/authorization/$', views.WeiboAuthURLView.as_view()),
    # 微博登陆后回调
    url(r'^oauth/sina/user/$', views.WeiboAuthUserView.as_view()),
    # 微博绑定用户
    url(r'^image_codes/(?P<image_codes>\w+)/$', views.WeiboImageCode.as_view())
]
