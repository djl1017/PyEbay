from django.conf.urls import urlfrom . import viewsurlpatterns = [    # 去结算    url(r'^orders/settlement/$', views.OrderSettlementView.as_view()),    # 保存订单    url(r'^orders/$', views.CommitOrderView.as_view()),    # 获取某一订单下所有未评论商品信息    url(r'^orders/(?P<order_id>\d+)/uncommentgoods/$', views.UncommentGoodsView.as_view()),    # 订单商品评论    url(r'^orders/(?P<order_id>\d+)/comments/$', views.GoodsJudgeView.as_view()),    # 获取某个SKU商品下所有评论    url(r'^skus/(?P<sku_id>\d+)/comments/$', views.SKUCommemtsView.as_view())]