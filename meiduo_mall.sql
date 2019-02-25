-- MySQL dump 10.13  Distrib 5.7.17, for Linux (x86_64)
--
-- Host: localhost    Database: meiduo_mall
-- ------------------------------------------------------
-- Server version	5.7.17-0ubuntu0.16.04.1-log

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `auth_group`
--

DROP TABLE IF EXISTS `auth_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(80) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group`
--

LOCK TABLES `auth_group` WRITE;
/*!40000 ALTER TABLE `auth_group` DISABLE KEYS */;
INSERT INTO `auth_group` VALUES (1,'test');
/*!40000 ALTER TABLE `auth_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group_permissions`
--

DROP TABLE IF EXISTS `auth_group_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group_permissions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_group_permissions_group_id_permission_id_0cd325b0_uniq` (`group_id`,`permission_id`),
  KEY `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_group_permissions_group_id_b120cbf9_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group_permissions`
--

LOCK TABLES `auth_group_permissions` WRITE;
/*!40000 ALTER TABLE `auth_group_permissions` DISABLE KEYS */;
INSERT INTO `auth_group_permissions` VALUES (1,1,1),(2,1,2),(3,1,3),(5,1,70),(4,1,117);
/*!40000 ALTER TABLE `auth_group_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_permission`
--

DROP TABLE IF EXISTS `auth_permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content_type_id` int(11) NOT NULL,
  `codename` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`),
  CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=126 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_permission`
--

LOCK TABLES `auth_permission` WRITE;
/*!40000 ALTER TABLE `auth_permission` DISABLE KEYS */;
INSERT INTO `auth_permission` VALUES (1,'Can add log entry',1,'add_logentry'),(2,'Can change log entry',1,'change_logentry'),(3,'Can delete log entry',1,'delete_logentry'),(4,'Can add permission',2,'add_permission'),(5,'Can change permission',2,'change_permission'),(6,'Can delete permission',2,'delete_permission'),(7,'Can add group',3,'add_group'),(8,'Can change group',3,'change_group'),(9,'Can delete group',3,'delete_group'),(10,'Can add content type',4,'add_contenttype'),(11,'Can change content type',4,'change_contenttype'),(12,'Can delete content type',4,'delete_contenttype'),(13,'Can add session',5,'add_session'),(14,'Can change session',5,'change_session'),(15,'Can delete session',5,'delete_session'),(16,'Can add 用户',6,'add_user'),(17,'Can change 用户',6,'change_user'),(18,'Can delete 用户',6,'delete_user'),(19,'Can add QQ登陆用户数据',7,'add_oauthqquser'),(20,'Can change QQ登陆用户数据',7,'change_oauthqquser'),(21,'Can delete QQ登陆用户数据',7,'delete_oauthqquser'),(22,'Can add 行政区划',8,'add_area'),(23,'Can change 行政区划',8,'change_area'),(24,'Can delete 行政区划',8,'delete_area'),(25,'Can add 用户地址',9,'add_address'),(26,'Can change 用户地址',9,'change_address'),(27,'Can delete 用户地址',9,'delete_address'),(28,'Can add 商品',10,'add_goods'),(29,'Can change 商品',10,'change_goods'),(30,'Can delete 商品',10,'delete_goods'),(31,'Can add SKU规格',11,'add_skuspecification'),(32,'Can change SKU规格',11,'change_skuspecification'),(33,'Can delete SKU规格',11,'delete_skuspecification'),(34,'Can add 商品SKU',12,'add_sku'),(35,'Can change 商品SKU',12,'change_sku'),(36,'Can delete 商品SKU',12,'delete_sku'),(37,'Can add goods channel',13,'add_goodschannel'),(38,'Can change goods channel',13,'change_goodschannel'),(39,'Can delete goods channel',13,'delete_goodschannel'),(40,'Can add 商品规格',14,'add_goodsspecification'),(41,'Can change 商品规格',14,'change_goodsspecification'),(42,'Can delete 商品规格',14,'delete_goodsspecification'),(43,'Can add 商品类别',15,'add_goodscategory'),(44,'Can change 商品类别',15,'change_goodscategory'),(45,'Can delete 商品类别',15,'delete_goodscategory'),(46,'Can add 规格选项',16,'add_specificationoption'),(47,'Can change 规格选项',16,'change_specificationoption'),(48,'Can delete 规格选项',16,'delete_specificationoption'),(49,'Can add SKU图片',17,'add_skuimage'),(50,'Can change SKU图片',17,'change_skuimage'),(51,'Can delete SKU图片',17,'delete_skuimage'),(52,'Can add 品牌',18,'add_brand'),(53,'Can change 品牌',18,'change_brand'),(54,'Can delete 品牌',18,'delete_brand'),(55,'Can add 广告内容类别',19,'add_contentcategory'),(56,'Can change 广告内容类别',19,'change_contentcategory'),(57,'Can delete 广告内容类别',19,'delete_contentcategory'),(58,'Can add 广告内容',20,'add_content'),(59,'Can change 广告内容',20,'change_content'),(60,'Can delete 广告内容',20,'delete_content'),(61,'Can add 订单商品',21,'add_ordergoods'),(62,'Can change 订单商品',21,'change_ordergoods'),(63,'Can delete 订单商品',21,'delete_ordergoods'),(64,'Can add 订单基本信息',22,'add_orderinfo'),(65,'Can change 订单基本信息',22,'change_orderinfo'),(66,'Can delete 订单基本信息',22,'delete_orderinfo'),(67,'Can add 支付信息',23,'add_payment'),(68,'Can change 支付信息',23,'change_payment'),(69,'Can delete 支付信息',23,'delete_payment'),(70,'Can view log entry',1,'view_logentry'),(71,'Can view 行政区划',8,'view_area'),(72,'Can view group',3,'view_group'),(73,'Can view permission',2,'view_permission'),(74,'Can view 广告内容',20,'view_content'),(75,'Can view 广告内容类别',19,'view_contentcategory'),(76,'Can view content type',4,'view_contenttype'),(77,'Can view 品牌',18,'view_brand'),(78,'Can view 商品',10,'view_goods'),(79,'Can view 商品类别',15,'view_goodscategory'),(80,'Can view 商品频道',13,'view_goodschannel'),(81,'Can view 商品规格',14,'view_goodsspecification'),(82,'Can view 商品SKU',12,'view_sku'),(83,'Can view SKU图片',17,'view_skuimage'),(84,'Can view SKU规格',11,'view_skuspecification'),(85,'Can view 规格选项',16,'view_specificationoption'),(86,'Can view QQ登陆用户数据',7,'view_oauthqquser'),(87,'Can view 订单商品',21,'view_ordergoods'),(88,'Can view 订单基本信息',22,'view_orderinfo'),(89,'Can view 支付信息',23,'view_payment'),(90,'Can view session',5,'view_session'),(91,'Can view 用户地址',9,'view_address'),(92,'Can view 用户',6,'view_user'),(93,'Can add log entry',24,'add_log'),(94,'Can change log entry',24,'change_log'),(95,'Can delete log entry',24,'delete_log'),(96,'Can add User Widget',25,'add_userwidget'),(97,'Can change User Widget',25,'change_userwidget'),(98,'Can delete User Widget',25,'delete_userwidget'),(99,'Can add Bookmark',26,'add_bookmark'),(100,'Can change Bookmark',26,'change_bookmark'),(101,'Can delete Bookmark',26,'delete_bookmark'),(102,'Can add User Setting',27,'add_usersettings'),(103,'Can change User Setting',27,'change_usersettings'),(104,'Can delete User Setting',27,'delete_usersettings'),(105,'Can view Bookmark',26,'view_bookmark'),(106,'Can view log entry',24,'view_log'),(107,'Can view User Setting',27,'view_usersettings'),(108,'Can view User Widget',25,'view_userwidget'),(109,'Can add revision',28,'add_revision'),(110,'Can change revision',28,'change_revision'),(111,'Can delete revision',28,'delete_revision'),(112,'Can add version',29,'add_version'),(113,'Can change version',29,'change_version'),(114,'Can delete version',29,'delete_version'),(115,'Can view revision',28,'view_revision'),(116,'Can view version',29,'view_version'),(117,'日志组',1,'１'),(118,'Can add 微博登陆用户数据',30,'add_oauthsinauser'),(119,'Can change 微博登陆用户数据',30,'change_oauthsinauser'),(120,'Can delete 微博登陆用户数据',30,'delete_oauthsinauser'),(121,'Can add QQ登录用户数据',31,'add_qqauthuser'),(122,'Can change QQ登录用户数据',31,'change_qqauthuser'),(123,'Can delete QQ登录用户数据',31,'delete_qqauthuser'),(124,'Can view 微博登陆用户数据',30,'view_oauthsinauser'),(125,'Can view QQ登录用户数据',31,'view_qqauthuser');
/*!40000 ALTER TABLE `auth_permission` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_admin_log`
--

DROP TABLE IF EXISTS `django_admin_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_admin_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `action_time` datetime(6) NOT NULL,
  `object_id` longtext,
  `object_repr` varchar(200) NOT NULL,
  `action_flag` smallint(5) unsigned NOT NULL,
  `change_message` longtext NOT NULL,
  `content_type_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `django_admin_log_content_type_id_c4bce8eb_fk_django_co` (`content_type_id`),
  KEY `django_admin_log_user_id_c564eba6_fk_tb_user_id` (`user_id`),
  CONSTRAINT `django_admin_log_content_type_id_c4bce8eb_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `django_admin_log_user_id_c564eba6_fk_tb_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_admin_log`
--

LOCK TABLES `django_admin_log` WRITE;
/*!40000 ALTER TABLE `django_admin_log` DISABLE KEYS */;
INSERT INTO `django_admin_log` VALUES (1,'2019-01-28 08:54:01.348446','555','代理代办',2,'[]',15,7),(2,'2019-02-12 03:56:00.753979','8','8: Apple iPhone 8 Plus (A1864) 256GB 银色 移动联通电信4G手机',2,'[]',12,7),(3,'2019-02-13 09:18:52.225437','2','2: Apple MacBook Pro 13.3英寸笔记本 深灰色',2,'[]',12,7),(4,'2019-02-13 09:18:59.081040','2','2: Apple MacBook Pro 13.3英寸笔记本 深灰色',2,'[]',12,7),(5,'2019-02-13 09:34:34.658333','1','1: Apple MacBook Pro 13.3英寸笔记本 银色',2,'[]',12,7);
/*!40000 ALTER TABLE `django_admin_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_content_type`
--

DROP TABLE IF EXISTS `django_content_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_content_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`)
) ENGINE=InnoDB AUTO_INCREMENT=32 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_content_type`
--

LOCK TABLES `django_content_type` WRITE;
/*!40000 ALTER TABLE `django_content_type` DISABLE KEYS */;
INSERT INTO `django_content_type` VALUES (1,'admin','logentry'),(8,'areas','area'),(3,'auth','group'),(2,'auth','permission'),(20,'contents','content'),(19,'contents','contentcategory'),(4,'contenttypes','contenttype'),(18,'goods','brand'),(10,'goods','goods'),(15,'goods','goodscategory'),(13,'goods','goodschannel'),(14,'goods','goodsspecification'),(12,'goods','sku'),(17,'goods','skuimage'),(11,'goods','skuspecification'),(16,'goods','specificationoption'),(7,'oauth','oauthqquser'),(30,'oauth','oauthsinauser'),(31,'oauth','qqauthuser'),(21,'orders','ordergoods'),(22,'orders','orderinfo'),(23,'payment','payment'),(28,'reversion','revision'),(29,'reversion','version'),(5,'sessions','session'),(9,'users','address'),(6,'users','user'),(26,'xadmin','bookmark'),(24,'xadmin','log'),(27,'xadmin','usersettings'),(25,'xadmin','userwidget');
/*!40000 ALTER TABLE `django_content_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_migrations`
--

DROP TABLE IF EXISTS `django_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_migrations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `applied` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=34 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_migrations`
--

LOCK TABLES `django_migrations` WRITE;
/*!40000 ALTER TABLE `django_migrations` DISABLE KEYS */;
INSERT INTO `django_migrations` VALUES (1,'contenttypes','0001_initial','2019-01-18 11:36:02.378362'),(2,'contenttypes','0002_remove_content_type_name','2019-01-18 11:36:02.447159'),(3,'auth','0001_initial','2019-01-18 11:36:02.669864'),(4,'auth','0002_alter_permission_name_max_length','2019-01-18 11:36:02.717446'),(5,'auth','0003_alter_user_email_max_length','2019-01-18 11:36:02.731240'),(6,'auth','0004_alter_user_username_opts','2019-01-18 11:36:02.744504'),(7,'auth','0005_alter_user_last_login_null','2019-01-18 11:36:02.758811'),(8,'auth','0006_require_contenttypes_0002','2019-01-18 11:36:02.762789'),(9,'auth','0007_alter_validators_add_error_messages','2019-01-18 11:36:02.781590'),(10,'auth','0008_alter_user_username_max_length','2019-01-18 11:36:02.800729'),(11,'users','0001_initial','2019-01-18 11:36:03.009758'),(12,'admin','0001_initial','2019-01-18 11:36:03.099561'),(13,'admin','0002_logentry_remove_auto_add','2019-01-18 11:36:03.126073'),(14,'sessions','0001_initial','2019-01-18 11:36:03.160018'),(15,'oauth','0001_initial','2019-01-22 07:34:05.741398'),(16,'users','0002_user_email_active','2019-01-24 06:57:27.574095'),(17,'areas','0001_initial','2019-01-24 12:18:18.101883'),(18,'areas','0002_auto_20190124_2018','2019-01-24 12:19:00.357453'),(19,'users','0003_address','2019-01-25 12:14:17.091261'),(20,'users','0004_user_default_address','2019-01-25 12:17:27.088556'),(22,'contents','0001_initial','2019-01-26 08:44:56.145930'),(25,'goods','0001_initial','2019-01-27 13:17:55.627722'),(26,'orders','0001_initial','2019-02-15 09:47:58.228194'),(27,'payment','0001_initial','2019-02-17 12:58:35.689522'),(28,'reversion','0001_squashed_0004_auto_20160611_1202','2019-02-17 14:56:30.328751'),(29,'xadmin','0001_initial','2019-02-17 14:56:30.608880'),(30,'xadmin','0002_log','2019-02-17 14:56:30.807733'),(31,'xadmin','0003_auto_20160715_0100','2019-02-17 14:56:30.865517'),(32,'oauth','0002_auto_20190223_1139','2019-02-23 04:15:16.988716'),(33,'orders','0002_auto_20190223_1139','2019-02-23 04:15:17.063171');
/*!40000 ALTER TABLE `django_migrations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_session`
--

DROP TABLE IF EXISTS `django_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_session` (
  `session_key` varchar(40) NOT NULL,
  `session_data` longtext NOT NULL,
  `expire_date` datetime(6) NOT NULL,
  PRIMARY KEY (`session_key`),
  KEY `django_session_expire_date_a5c62663` (`expire_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_session`
--

LOCK TABLES `django_session` WRITE;
/*!40000 ALTER TABLE `django_session` DISABLE KEYS */;
/*!40000 ALTER TABLE `django_session` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `reversion_revision`
--

DROP TABLE IF EXISTS `reversion_revision`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `reversion_revision` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `date_created` datetime(6) NOT NULL,
  `comment` longtext NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `reversion_revision_user_id_17095f45_fk_tb_user_id` (`user_id`),
  KEY `reversion_revision_date_created_96f7c20c` (`date_created`),
  CONSTRAINT `reversion_revision_user_id_17095f45_fk_tb_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reversion_revision`
--

LOCK TABLES `reversion_revision` WRITE;
/*!40000 ALTER TABLE `reversion_revision` DISABLE KEYS */;
/*!40000 ALTER TABLE `reversion_revision` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `reversion_version`
--

DROP TABLE IF EXISTS `reversion_version`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `reversion_version` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `object_id` varchar(191) NOT NULL,
  `format` varchar(255) NOT NULL,
  `serialized_data` longtext NOT NULL,
  `object_repr` longtext NOT NULL,
  `content_type_id` int(11) NOT NULL,
  `revision_id` int(11) NOT NULL,
  `db` varchar(191) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `reversion_version_db_content_type_id_objec_b2c54f65_uniq` (`db`,`content_type_id`,`object_id`,`revision_id`),
  KEY `reversion_version_content_type_id_7d0ff25c_fk_django_co` (`content_type_id`),
  KEY `reversion_version_revision_id_af9f6a9d_fk_reversion_revision_id` (`revision_id`),
  CONSTRAINT `reversion_version_content_type_id_7d0ff25c_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `reversion_version_revision_id_af9f6a9d_fk_reversion_revision_id` FOREIGN KEY (`revision_id`) REFERENCES `reversion_revision` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `reversion_version`
--

LOCK TABLES `reversion_version` WRITE;
/*!40000 ALTER TABLE `reversion_version` DISABLE KEYS */;
/*!40000 ALTER TABLE `reversion_version` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_address`
--

DROP TABLE IF EXISTS `tb_address`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_address` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `title` varchar(20) NOT NULL,
  `receiver` varchar(20) NOT NULL,
  `place` varchar(50) NOT NULL,
  `mobile` varchar(11) NOT NULL,
  `tel` varchar(20) DEFAULT NULL,
  `email` varchar(50) DEFAULT NULL,
  `is_deleted` tinyint(1) NOT NULL,
  `city_id` int(11) NOT NULL,
  `district_id` int(11) NOT NULL,
  `province_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_address_city_id_bcf28c8d_fk_tb_areas_id` (`city_id`),
  KEY `tb_address_district_id_d2c72fb7_fk_tb_areas_id` (`district_id`),
  KEY `tb_address_province_id_408b3227_fk_tb_areas_id` (`province_id`),
  KEY `tb_address_user_id_476bb898_fk_tb_user_id` (`user_id`),
  CONSTRAINT `tb_address_city_id_bcf28c8d_fk_tb_areas_id` FOREIGN KEY (`city_id`) REFERENCES `tb_areas` (`id`),
  CONSTRAINT `tb_address_district_id_d2c72fb7_fk_tb_areas_id` FOREIGN KEY (`district_id`) REFERENCES `tb_areas` (`id`),
  CONSTRAINT `tb_address_province_id_408b3227_fk_tb_areas_id` FOREIGN KEY (`province_id`) REFERENCES `tb_areas` (`id`),
  CONSTRAINT `tb_address_user_id_476bb898_fk_tb_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_address`
--

LOCK TABLES `tb_address` WRITE;
/*!40000 ALTER TABLE `tb_address` DISABLE KEYS */;
INSERT INTO `tb_address` VALUES (1,'2019-01-26 06:43:15.331866','2019-01-26 07:17:13.448736','测试11','测试','测试地址','13412345678','','',1,130300,130304,130000,1),(2,'2019-01-26 07:17:55.002038','2019-01-26 07:17:55.002113','测试１','测试１','测试地址１２３','13412345678','','',0,210300,210304,210000,1),(3,'2019-02-17 09:13:21.452001','2019-02-17 09:13:21.452090','ahacha','ahacha','吃嫩城市克陈女士','13434792337','','',0,130300,130303,130000,2),(4,'2019-02-23 03:57:46.139842','2019-02-24 10:00:29.790152','edfgsdf444','edfgsdf444','sdfsdfs','18697656554','','',0,150400,150421,150000,8),(5,'2019-02-23 11:46:11.115922','2019-02-23 11:46:11.116112','sdfsdf','sdfsdf','sdfsdf','18696372667','','',0,150400,150421,150000,11);
/*!40000 ALTER TABLE `tb_address` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_areas`
--

DROP TABLE IF EXISTS `tb_areas`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_areas` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(20) NOT NULL,
  `parent_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_table_parent_id_54d44b26_fk_tb_table_id` (`parent_id`),
  CONSTRAINT `tb_table_parent_id_54d44b26_fk_tb_table_id` FOREIGN KEY (`parent_id`) REFERENCES `tb_areas` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=820001 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_areas`
--

LOCK TABLES `tb_areas` WRITE;
/*!40000 ALTER TABLE `tb_areas` DISABLE KEYS */;
INSERT INTO `tb_areas` VALUES (110000,'北京市',NULL),(110100,'北京市',110000),(110101,'东城区',110100),(110102,'西城区',110100),(110105,'朝阳区',110100),(110106,'丰台区',110100),(110107,'石景山区',110100),(110108,'海淀区',110100),(110109,'门头沟区',110100),(110111,'房山区',110100),(110112,'通州区',110100),(110113,'顺义区',110100),(110114,'昌平区',110100),(110115,'大兴区',110100),(110116,'怀柔区',110100),(110117,'平谷区',110100),(110118,'密云区',110100),(110119,'延庆区',110100),(120000,'天津市',NULL),(120100,'天津市',120000),(120101,'和平区',120100),(120102,'河东区',120100),(120103,'河西区',120100),(120104,'南开区',120100),(120105,'河北区',120100),(120106,'红桥区',120100),(120110,'东丽区',120100),(120111,'西青区',120100),(120112,'津南区',120100),(120113,'北辰区',120100),(120114,'武清区',120100),(120115,'宝坻区',120100),(120116,'滨海新区',120100),(120117,'宁河区',120100),(120118,'静海区',120100),(120119,'蓟州区',120100),(130000,'河北省',NULL),(130100,'石家庄市',130000),(130102,'长安区',130100),(130104,'桥西区',130100),(130105,'新华区',130100),(130107,'井陉矿区',130100),(130108,'裕华区',130100),(130109,'藁城区',130100),(130110,'鹿泉区',130100),(130111,'栾城区',130100),(130121,'井陉县',130100),(130123,'正定县',130100),(130125,'行唐县',130100),(130126,'灵寿县',130100),(130127,'高邑县',130100),(130128,'深泽县',130100),(130129,'赞皇县',130100),(130130,'无极县',130100),(130131,'平山县',130100),(130132,'元氏县',130100),(130133,'赵县',130100),(130183,'晋州市',130100),(130184,'新乐市',130100),(130200,'唐山市',130000),(130202,'路南区',130200),(130203,'路北区',130200),(130204,'古冶区',130200),(130205,'开平区',130200),(130207,'丰南区',130200),(130208,'丰润区',130200),(130209,'曹妃甸区',130200),(130223,'滦县',130200),(130224,'滦南县',130200),(130225,'乐亭县',130200),(130227,'迁西县',130200),(130229,'玉田县',130200),(130281,'遵化市',130200),(130283,'迁安市',130200),(130300,'秦皇岛市',130000),(130302,'海港区',130300),(130303,'山海关区',130300),(130304,'北戴河区',130300),(130306,'抚宁区',130300),(130321,'青龙满族自治县',130300),(130322,'昌黎县',130300),(130324,'卢龙县',130300),(130400,'邯郸市',130000),(130402,'邯山区',130400),(130403,'丛台区',130400),(130404,'复兴区',130400),(130406,'峰峰矿区',130400),(130421,'邯郸县',130400),(130423,'临漳县',130400),(130424,'成安县',130400),(130425,'大名县',130400),(130426,'涉县',130400),(130427,'磁县',130400),(130428,'肥乡县',130400),(130429,'永年县',130400),(130430,'邱县',130400),(130431,'鸡泽县',130400),(130432,'广平县',130400),(130433,'馆陶县',130400),(130434,'魏县',130400),(130435,'曲周县',130400),(130481,'武安市',130400),(130500,'邢台市',130000),(130502,'桥东区',130500),(130503,'桥西区',130500),(130521,'邢台县',130500),(130522,'临城县',130500),(130523,'内丘县',130500),(130524,'柏乡县',130500),(130525,'隆尧县',130500),(130526,'任县',130500),(130527,'南和县',130500),(130528,'宁晋县',130500),(130529,'巨鹿县',130500),(130530,'新河县',130500),(130531,'广宗县',130500),(130532,'平乡县',130500),(130533,'威县',130500),(130534,'清河县',130500),(130535,'临西县',130500),(130581,'南宫市',130500),(130582,'沙河市',130500),(130600,'保定市',130000),(130602,'竞秀区',130600),(130606,'莲池区',130600),(130607,'满城区',130600),(130608,'清苑区',130600),(130609,'徐水区',130600),(130623,'涞水县',130600),(130624,'阜平县',130600),(130626,'定兴县',130600),(130627,'唐县',130600),(130628,'高阳县',130600),(130629,'容城县',130600),(130630,'涞源县',130600),(130631,'望都县',130600),(130632,'安新县',130600),(130633,'易县',130600),(130634,'曲阳县',130600),(130635,'蠡县',130600),(130636,'顺平县',130600),(130637,'博野县',130600),(130638,'雄县',130600),(130681,'涿州市',130600),(130683,'安国市',130600),(130684,'高碑店市',130600),(130700,'张家口市',130000),(130702,'桥东区',130700),(130703,'桥西区',130700),(130705,'宣化区',130700),(130706,'下花园区',130700),(130708,'万全区',130700),(130709,'崇礼区',130700),(130722,'张北县',130700),(130723,'康保县',130700),(130724,'沽源县',130700),(130725,'尚义县',130700),(130726,'蔚县',130700),(130727,'阳原县',130700),(130728,'怀安县',130700),(130730,'怀来县',130700),(130731,'涿鹿县',130700),(130732,'赤城县',130700),(130800,'承德市',130000),(130802,'双桥区',130800),(130803,'双滦区',130800),(130804,'鹰手营子矿区',130800),(130821,'承德县',130800),(130822,'兴隆县',130800),(130823,'平泉县',130800),(130824,'滦平县',130800),(130825,'隆化县',130800),(130826,'丰宁满族自治县',130800),(130827,'宽城满族自治县',130800),(130828,'围场满族蒙古族自治县',130800),(130900,'沧州市',130000),(130902,'新华区',130900),(130903,'运河区',130900),(130921,'沧县',130900),(130922,'青县',130900),(130923,'东光县',130900),(130924,'海兴县',130900),(130925,'盐山县',130900),(130926,'肃宁县',130900),(130927,'南皮县',130900),(130928,'吴桥县',130900),(130929,'献县',130900),(130930,'孟村回族自治县',130900),(130981,'泊头市',130900),(130982,'任丘市',130900),(130983,'黄骅市',130900),(130984,'河间市',130900),(131000,'廊坊市',130000),(131002,'安次区',131000),(131003,'广阳区',131000),(131022,'固安县',131000),(131023,'永清县',131000),(131024,'香河县',131000),(131025,'大城县',131000),(131026,'文安县',131000),(131028,'大厂回族自治县',131000),(131081,'霸州市',131000),(131082,'三河市',131000),(131100,'衡水市',130000),(131102,'桃城区',131100),(131103,'冀州区',131100),(131121,'枣强县',131100),(131122,'武邑县',131100),(131123,'武强县',131100),(131124,'饶阳县',131100),(131125,'安平县',131100),(131126,'故城县',131100),(131127,'景县',131100),(131128,'阜城县',131100),(131182,'深州市',131100),(139000,'省直辖县级行政区划',130000),(139001,'定州市',139000),(139002,'辛集市',139000),(140000,'山西省',NULL),(140100,'太原市',140000),(140105,'小店区',140100),(140106,'迎泽区',140100),(140107,'杏花岭区',140100),(140108,'尖草坪区',140100),(140109,'万柏林区',140100),(140110,'晋源区',140100),(140121,'清徐县',140100),(140122,'阳曲县',140100),(140123,'娄烦县',140100),(140181,'古交市',140100),(140200,'大同市',140000),(140202,'城区',140200),(140203,'矿区',140200),(140211,'南郊区',140200),(140212,'新荣区',140200),(140221,'阳高县',140200),(140222,'天镇县',140200),(140223,'广灵县',140200),(140224,'灵丘县',140200),(140225,'浑源县',140200),(140226,'左云县',140200),(140227,'大同县',140200),(140300,'阳泉市',140000),(140302,'城区',140300),(140303,'矿区',140300),(140311,'郊区',140300),(140321,'平定县',140300),(140322,'盂县',140300),(140400,'长治市',140000),(140402,'城区',140400),(140411,'郊区',140400),(140421,'长治县',140400),(140423,'襄垣县',140400),(140424,'屯留县',140400),(140425,'平顺县',140400),(140426,'黎城县',140400),(140427,'壶关县',140400),(140428,'长子县',140400),(140429,'武乡县',140400),(140430,'沁县',140400),(140431,'沁源县',140400),(140481,'潞城市',140400),(140500,'晋城市',140000),(140502,'城区',140500),(140521,'沁水县',140500),(140522,'阳城县',140500),(140524,'陵川县',140500),(140525,'泽州县',140500),(140581,'高平市',140500),(140600,'朔州市',140000),(140602,'朔城区',140600),(140603,'平鲁区',140600),(140621,'山阴县',140600),(140622,'应县',140600),(140623,'右玉县',140600),(140624,'怀仁县',140600),(140700,'晋中市',140000),(140702,'榆次区',140700),(140721,'榆社县',140700),(140722,'左权县',140700),(140723,'和顺县',140700),(140724,'昔阳县',140700),(140725,'寿阳县',140700),(140726,'太谷县',140700),(140727,'祁县',140700),(140728,'平遥县',140700),(140729,'灵石县',140700),(140781,'介休市',140700),(140800,'运城市',140000),(140802,'盐湖区',140800),(140821,'临猗县',140800),(140822,'万荣县',140800),(140823,'闻喜县',140800),(140824,'稷山县',140800),(140825,'新绛县',140800),(140826,'绛县',140800),(140827,'垣曲县',140800),(140828,'夏县',140800),(140829,'平陆县',140800),(140830,'芮城县',140800),(140881,'永济市',140800),(140882,'河津市',140800),(140900,'忻州市',140000),(140902,'忻府区',140900),(140921,'定襄县',140900),(140922,'五台县',140900),(140923,'代县',140900),(140924,'繁峙县',140900),(140925,'宁武县',140900),(140926,'静乐县',140900),(140927,'神池县',140900),(140928,'五寨县',140900),(140929,'岢岚县',140900),(140930,'河曲县',140900),(140931,'保德县',140900),(140932,'偏关县',140900),(140981,'原平市',140900),(141000,'临汾市',140000),(141002,'尧都区',141000),(141021,'曲沃县',141000),(141022,'翼城县',141000),(141023,'襄汾县',141000),(141024,'洪洞县',141000),(141025,'古县',141000),(141026,'安泽县',141000),(141027,'浮山县',141000),(141028,'吉县',141000),(141029,'乡宁县',141000),(141030,'大宁县',141000),(141031,'隰县',141000),(141032,'永和县',141000),(141033,'蒲县',141000),(141034,'汾西县',141000),(141081,'侯马市',141000),(141082,'霍州市',141000),(141100,'吕梁市',140000),(141102,'离石区',141100),(141121,'文水县',141100),(141122,'交城县',141100),(141123,'兴县',141100),(141124,'临县',141100),(141125,'柳林县',141100),(141126,'石楼县',141100),(141127,'岚县',141100),(141128,'方山县',141100),(141129,'中阳县',141100),(141130,'交口县',141100),(141181,'孝义市',141100),(141182,'汾阳市',141100),(150000,'内蒙古自治区',NULL),(150100,'呼和浩特市',150000),(150102,'新城区',150100),(150103,'回民区',150100),(150104,'玉泉区',150100),(150105,'赛罕区',150100),(150121,'土默特左旗',150100),(150122,'托克托县',150100),(150123,'和林格尔县',150100),(150124,'清水河县',150100),(150125,'武川县',150100),(150200,'包头市',150000),(150202,'东河区',150200),(150203,'昆都仑区',150200),(150204,'青山区',150200),(150205,'石拐区',150200),(150206,'白云鄂博矿区',150200),(150207,'九原区',150200),(150221,'土默特右旗',150200),(150222,'固阳县',150200),(150223,'达尔罕茂明安联合旗',150200),(150300,'乌海市',150000),(150302,'海勃湾区',150300),(150303,'海南区',150300),(150304,'乌达区',150300),(150400,'赤峰市',150000),(150402,'红山区',150400),(150403,'元宝山区',150400),(150404,'松山区',150400),(150421,'阿鲁科尔沁旗',150400),(150422,'巴林左旗',150400),(150423,'巴林右旗',150400),(150424,'林西县',150400),(150425,'克什克腾旗',150400),(150426,'翁牛特旗',150400),(150428,'喀喇沁旗',150400),(150429,'宁城县',150400),(150430,'敖汉旗',150400),(150500,'通辽市',150000),(150502,'科尔沁区',150500),(150521,'科尔沁左翼中旗',150500),(150522,'科尔沁左翼后旗',150500),(150523,'开鲁县',150500),(150524,'库伦旗',150500),(150525,'奈曼旗',150500),(150526,'扎鲁特旗',150500),(150581,'霍林郭勒市',150500),(150600,'鄂尔多斯市',150000),(150602,'东胜区',150600),(150603,'康巴什区',150600),(150621,'达拉特旗',150600),(150622,'准格尔旗',150600),(150623,'鄂托克前旗',150600),(150624,'鄂托克旗',150600),(150625,'杭锦旗',150600),(150626,'乌审旗',150600),(150627,'伊金霍洛旗',150600),(150700,'呼伦贝尔市',150000),(150702,'海拉尔区',150700),(150703,'扎赉诺尔区',150700),(150721,'阿荣旗',150700),(150722,'莫力达瓦达斡尔族自治旗',150700),(150723,'鄂伦春自治旗',150700),(150724,'鄂温克族自治旗',150700),(150725,'陈巴尔虎旗',150700),(150726,'新巴尔虎左旗',150700),(150727,'新巴尔虎右旗',150700),(150781,'满洲里市',150700),(150782,'牙克石市',150700),(150783,'扎兰屯市',150700),(150784,'额尔古纳市',150700),(150785,'根河市',150700),(150800,'巴彦淖尔市',150000),(150802,'临河区',150800),(150821,'五原县',150800),(150822,'磴口县',150800),(150823,'乌拉特前旗',150800),(150824,'乌拉特中旗',150800),(150825,'乌拉特后旗',150800),(150826,'杭锦后旗',150800),(150900,'乌兰察布市',150000),(150902,'集宁区',150900),(150921,'卓资县',150900),(150922,'化德县',150900),(150923,'商都县',150900),(150924,'兴和县',150900),(150925,'凉城县',150900),(150926,'察哈尔右翼前旗',150900),(150927,'察哈尔右翼中旗',150900),(150928,'察哈尔右翼后旗',150900),(150929,'四子王旗',150900),(150981,'丰镇市',150900),(152200,'兴安盟',150000),(152201,'乌兰浩特市',152200),(152202,'阿尔山市',152200),(152221,'科尔沁右翼前旗',152200),(152222,'科尔沁右翼中旗',152200),(152223,'扎赉特旗',152200),(152224,'突泉县',152200),(152500,'锡林郭勒盟',150000),(152501,'二连浩特市',152500),(152502,'锡林浩特市',152500),(152522,'阿巴嘎旗',152500),(152523,'苏尼特左旗',152500),(152524,'苏尼特右旗',152500),(152525,'东乌珠穆沁旗',152500),(152526,'西乌珠穆沁旗',152500),(152527,'太仆寺旗',152500),(152528,'镶黄旗',152500),(152529,'正镶白旗',152500),(152530,'正蓝旗',152500),(152531,'多伦县',152500),(152900,'阿拉善盟',150000),(152921,'阿拉善左旗',152900),(152922,'阿拉善右旗',152900),(152923,'额济纳旗',152900),(210000,'辽宁省',NULL),(210100,'沈阳市',210000),(210102,'和平区',210100),(210103,'沈河区',210100),(210104,'大东区',210100),(210105,'皇姑区',210100),(210106,'铁西区',210100),(210111,'苏家屯区',210100),(210112,'浑南区',210100),(210113,'沈北新区',210100),(210114,'于洪区',210100),(210115,'辽中区',210100),(210123,'康平县',210100),(210124,'法库县',210100),(210181,'新民市',210100),(210200,'大连市',210000),(210202,'中山区',210200),(210203,'西岗区',210200),(210204,'沙河口区',210200),(210211,'甘井子区',210200),(210212,'旅顺口区',210200),(210213,'金州区',210200),(210214,'普兰店区',210200),(210224,'长海县',210200),(210281,'瓦房店市',210200),(210283,'庄河市',210200),(210300,'鞍山市',210000),(210302,'铁东区',210300),(210303,'铁西区',210300),(210304,'立山区',210300),(210311,'千山区',210300),(210321,'台安县',210300),(210323,'岫岩满族自治县',210300),(210381,'海城市',210300),(210400,'抚顺市',210000),(210402,'新抚区',210400),(210403,'东洲区',210400),(210404,'望花区',210400),(210411,'顺城区',210400),(210421,'抚顺县',210400),(210422,'新宾满族自治县',210400),(210423,'清原满族自治县',210400),(210500,'本溪市',210000),(210502,'平山区',210500),(210503,'溪湖区',210500),(210504,'明山区',210500),(210505,'南芬区',210500),(210521,'本溪满族自治县',210500),(210522,'桓仁满族自治县',210500),(210600,'丹东市',210000),(210602,'元宝区',210600),(210603,'振兴区',210600),(210604,'振安区',210600),(210624,'宽甸满族自治县',210600),(210681,'东港市',210600),(210682,'凤城市',210600),(210700,'锦州市',210000),(210702,'古塔区',210700),(210703,'凌河区',210700),(210711,'太和区',210700),(210726,'黑山县',210700),(210727,'义县',210700),(210781,'凌海市',210700),(210782,'北镇市',210700),(210800,'营口市',210000),(210802,'站前区',210800),(210803,'西市区',210800),(210804,'鲅鱼圈区',210800),(210811,'老边区',210800),(210881,'盖州市',210800),(210882,'大石桥市',210800),(210900,'阜新市',210000),(210902,'海州区',210900),(210903,'新邱区',210900),(210904,'太平区',210900),(210905,'清河门区',210900),(210911,'细河区',210900),(210921,'阜新蒙古族自治县',210900),(210922,'彰武县',210900),(211000,'辽阳市',210000),(211002,'白塔区',211000),(211003,'文圣区',211000),(211004,'宏伟区',211000),(211005,'弓长岭区',211000),(211011,'太子河区',211000),(211021,'辽阳县',211000),(211081,'灯塔市',211000),(211100,'盘锦市',210000),(211102,'双台子区',211100),(211103,'兴隆台区',211100),(211104,'大洼区',211100),(211122,'盘山县',211100),(211200,'铁岭市',210000),(211202,'银州区',211200),(211204,'清河区',211200),(211221,'铁岭县',211200),(211223,'西丰县',211200),(211224,'昌图县',211200),(211281,'调兵山市',211200),(211282,'开原市',211200),(211300,'朝阳市',210000),(211302,'双塔区',211300),(211303,'龙城区',211300),(211321,'朝阳县',211300),(211322,'建平县',211300),(211324,'喀喇沁左翼蒙古族自治县',211300),(211381,'北票市',211300),(211382,'凌源市',211300),(211400,'葫芦岛市',210000),(211402,'连山区',211400),(211403,'龙港区',211400),(211404,'南票区',211400),(211421,'绥中县',211400),(211422,'建昌县',211400),(211481,'兴城市',211400),(220000,'吉林省',NULL),(220100,'长春市',220000),(220102,'南关区',220100),(220103,'宽城区',220100),(220104,'朝阳区',220100),(220105,'二道区',220100),(220106,'绿园区',220100),(220112,'双阳区',220100),(220113,'九台区',220100),(220122,'农安县',220100),(220182,'榆树市',220100),(220183,'德惠市',220100),(220200,'吉林市',220000),(220202,'昌邑区',220200),(220203,'龙潭区',220200),(220204,'船营区',220200),(220211,'丰满区',220200),(220221,'永吉县',220200),(220281,'蛟河市',220200),(220282,'桦甸市',220200),(220283,'舒兰市',220200),(220284,'磐石市',220200),(220300,'四平市',220000),(220302,'铁西区',220300),(220303,'铁东区',220300),(220322,'梨树县',220300),(220323,'伊通满族自治县',220300),(220381,'公主岭市',220300),(220382,'双辽市',220300),(220400,'辽源市',220000),(220402,'龙山区',220400),(220403,'西安区',220400),(220421,'东丰县',220400),(220422,'东辽县',220400),(220500,'通化市',220000),(220502,'东昌区',220500),(220503,'二道江区',220500),(220521,'通化县',220500),(220523,'辉南县',220500),(220524,'柳河县',220500),(220581,'梅河口市',220500),(220582,'集安市',220500),(220600,'白山市',220000),(220602,'浑江区',220600),(220605,'江源区',220600),(220621,'抚松县',220600),(220622,'靖宇县',220600),(220623,'长白朝鲜族自治县',220600),(220681,'临江市',220600),(220700,'松原市',220000),(220702,'宁江区',220700),(220721,'前郭尔罗斯蒙古族自治县',220700),(220722,'长岭县',220700),(220723,'乾安县',220700),(220781,'扶余市',220700),(220800,'白城市',220000),(220802,'洮北区',220800),(220821,'镇赉县',220800),(220822,'通榆县',220800),(220881,'洮南市',220800),(220882,'大安市',220800),(222400,'延边朝鲜族自治州',220000),(222401,'延吉市',222400),(222402,'图们市',222400),(222403,'敦化市',222400),(222404,'珲春市',222400),(222405,'龙井市',222400),(222406,'和龙市',222400),(222424,'汪清县',222400),(222426,'安图县',222400),(230000,'黑龙江省',NULL),(230100,'哈尔滨市',230000),(230102,'道里区',230100),(230103,'南岗区',230100),(230104,'道外区',230100),(230108,'平房区',230100),(230109,'松北区',230100),(230110,'香坊区',230100),(230111,'呼兰区',230100),(230112,'阿城区',230100),(230113,'双城区',230100),(230123,'依兰县',230100),(230124,'方正县',230100),(230125,'宾县',230100),(230126,'巴彦县',230100),(230127,'木兰县',230100),(230128,'通河县',230100),(230129,'延寿县',230100),(230183,'尚志市',230100),(230184,'五常市',230100),(230200,'齐齐哈尔市',230000),(230202,'龙沙区',230200),(230203,'建华区',230200),(230204,'铁锋区',230200),(230205,'昂昂溪区',230200),(230206,'富拉尔基区',230200),(230207,'碾子山区',230200),(230208,'梅里斯达斡尔族区',230200),(230221,'龙江县',230200),(230223,'依安县',230200),(230224,'泰来县',230200),(230225,'甘南县',230200),(230227,'富裕县',230200),(230229,'克山县',230200),(230230,'克东县',230200),(230231,'拜泉县',230200),(230281,'讷河市',230200),(230300,'鸡西市',230000),(230302,'鸡冠区',230300),(230303,'恒山区',230300),(230304,'滴道区',230300),(230305,'梨树区',230300),(230306,'城子河区',230300),(230307,'麻山区',230300),(230321,'鸡东县',230300),(230381,'虎林市',230300),(230382,'密山市',230300),(230400,'鹤岗市',230000),(230402,'向阳区',230400),(230403,'工农区',230400),(230404,'南山区',230400),(230405,'兴安区',230400),(230406,'东山区',230400),(230407,'兴山区',230400),(230421,'萝北县',230400),(230422,'绥滨县',230400),(230500,'双鸭山市',230000),(230502,'尖山区',230500),(230503,'岭东区',230500),(230505,'四方台区',230500),(230506,'宝山区',230500),(230521,'集贤县',230500),(230522,'友谊县',230500),(230523,'宝清县',230500),(230524,'饶河县',230500),(230600,'大庆市',230000),(230602,'萨尔图区',230600),(230603,'龙凤区',230600),(230604,'让胡路区',230600),(230605,'红岗区',230600),(230606,'大同区',230600),(230621,'肇州县',230600),(230622,'肇源县',230600),(230623,'林甸县',230600),(230624,'杜尔伯特蒙古族自治县',230600),(230700,'伊春市',230000),(230702,'伊春区',230700),(230703,'南岔区',230700),(230704,'友好区',230700),(230705,'西林区',230700),(230706,'翠峦区',230700),(230707,'新青区',230700),(230708,'美溪区',230700),(230709,'金山屯区',230700),(230710,'五营区',230700),(230711,'乌马河区',230700),(230712,'汤旺河区',230700),(230713,'带岭区',230700),(230714,'乌伊岭区',230700),(230715,'红星区',230700),(230716,'上甘岭区',230700),(230722,'嘉荫县',230700),(230781,'铁力市',230700),(230800,'佳木斯市',230000),(230803,'向阳区',230800),(230804,'前进区',230800),(230805,'东风区',230800),(230811,'郊区',230800),(230822,'桦南县',230800),(230826,'桦川县',230800),(230828,'汤原县',230800),(230881,'同江市',230800),(230882,'富锦市',230800),(230883,'抚远市',230800),(230900,'七台河市',230000),(230902,'新兴区',230900),(230903,'桃山区',230900),(230904,'茄子河区',230900),(230921,'勃利县',230900),(231000,'牡丹江市',230000),(231002,'东安区',231000),(231003,'阳明区',231000),(231004,'爱民区',231000),(231005,'西安区',231000),(231025,'林口县',231000),(231081,'绥芬河市',231000),(231083,'海林市',231000),(231084,'宁安市',231000),(231085,'穆棱市',231000),(231086,'东宁市',231000),(231100,'黑河市',230000),(231102,'爱辉区',231100),(231121,'嫩江县',231100),(231123,'逊克县',231100),(231124,'孙吴县',231100),(231181,'北安市',231100),(231182,'五大连池市',231100),(231200,'绥化市',230000),(231202,'北林区',231200),(231221,'望奎县',231200),(231222,'兰西县',231200),(231223,'青冈县',231200),(231224,'庆安县',231200),(231225,'明水县',231200),(231226,'绥棱县',231200),(231281,'安达市',231200),(231282,'肇东市',231200),(231283,'海伦市',231200),(232700,'大兴安岭地区',230000),(232721,'呼玛县',232700),(232722,'塔河县',232700),(232723,'漠河县',232700),(310000,'上海市',NULL),(310100,'上海市',310000),(310101,'黄浦区',310100),(310104,'徐汇区',310100),(310105,'长宁区',310100),(310106,'静安区',310100),(310107,'普陀区',310100),(310109,'虹口区',310100),(310110,'杨浦区',310100),(310112,'闵行区',310100),(310113,'宝山区',310100),(310114,'嘉定区',310100),(310115,'浦东新区',310100),(310116,'金山区',310100),(310117,'松江区',310100),(310118,'青浦区',310100),(310120,'奉贤区',310100),(310151,'崇明区',310100),(320000,'江苏省',NULL),(320100,'南京市',320000),(320102,'玄武区',320100),(320104,'秦淮区',320100),(320105,'建邺区',320100),(320106,'鼓楼区',320100),(320111,'浦口区',320100),(320113,'栖霞区',320100),(320114,'雨花台区',320100),(320115,'江宁区',320100),(320116,'六合区',320100),(320117,'溧水区',320100),(320118,'高淳区',320100),(320200,'无锡市',320000),(320205,'锡山区',320200),(320206,'惠山区',320200),(320211,'滨湖区',320200),(320213,'梁溪区',320200),(320214,'新吴区',320200),(320281,'江阴市',320200),(320282,'宜兴市',320200),(320300,'徐州市',320000),(320302,'鼓楼区',320300),(320303,'云龙区',320300),(320305,'贾汪区',320300),(320311,'泉山区',320300),(320312,'铜山区',320300),(320321,'丰县',320300),(320322,'沛县',320300),(320324,'睢宁县',320300),(320381,'新沂市',320300),(320382,'邳州市',320300),(320400,'常州市',320000),(320402,'天宁区',320400),(320404,'钟楼区',320400),(320411,'新北区',320400),(320412,'武进区',320400),(320413,'金坛区',320400),(320481,'溧阳市',320400),(320500,'苏州市',320000),(320505,'虎丘区',320500),(320506,'吴中区',320500),(320507,'相城区',320500),(320508,'姑苏区',320500),(320509,'吴江区',320500),(320581,'常熟市',320500),(320582,'张家港市',320500),(320583,'昆山市',320500),(320585,'太仓市',320500),(320600,'南通市',320000),(320602,'崇川区',320600),(320611,'港闸区',320600),(320612,'通州区',320600),(320621,'海安县',320600),(320623,'如东县',320600),(320681,'启东市',320600),(320682,'如皋市',320600),(320684,'海门市',320600),(320700,'连云港市',320000),(320703,'连云区',320700),(320706,'海州区',320700),(320707,'赣榆区',320700),(320722,'东海县',320700),(320723,'灌云县',320700),(320724,'灌南县',320700),(320800,'淮安市',320000),(320803,'淮安区',320800),(320804,'淮阴区',320800),(320812,'清江浦区',320800),(320813,'洪泽区',320800),(320826,'涟水县',320800),(320830,'盱眙县',320800),(320831,'金湖县',320800),(320900,'盐城市',320000),(320902,'亭湖区',320900),(320903,'盐都区',320900),(320904,'大丰区',320900),(320921,'响水县',320900),(320922,'滨海县',320900),(320923,'阜宁县',320900),(320924,'射阳县',320900),(320925,'建湖县',320900),(320981,'东台市',320900),(321000,'扬州市',320000),(321002,'广陵区',321000),(321003,'邗江区',321000),(321012,'江都区',321000),(321023,'宝应县',321000),(321081,'仪征市',321000),(321084,'高邮市',321000),(321100,'镇江市',320000),(321102,'京口区',321100),(321111,'润州区',321100),(321112,'丹徒区',321100),(321181,'丹阳市',321100),(321182,'扬中市',321100),(321183,'句容市',321100),(321200,'泰州市',320000),(321202,'海陵区',321200),(321203,'高港区',321200),(321204,'姜堰区',321200),(321281,'兴化市',321200),(321282,'靖江市',321200),(321283,'泰兴市',321200),(321300,'宿迁市',320000),(321302,'宿城区',321300),(321311,'宿豫区',321300),(321322,'沭阳县',321300),(321323,'泗阳县',321300),(321324,'泗洪县',321300),(330000,'浙江省',NULL),(330100,'杭州市',330000),(330102,'上城区',330100),(330103,'下城区',330100),(330104,'江干区',330100),(330105,'拱墅区',330100),(330106,'西湖区',330100),(330108,'滨江区',330100),(330109,'萧山区',330100),(330110,'余杭区',330100),(330111,'富阳区',330100),(330122,'桐庐县',330100),(330127,'淳安县',330100),(330182,'建德市',330100),(330185,'临安市',330100),(330200,'宁波市',330000),(330203,'海曙区',330200),(330204,'江东区',330200),(330205,'江北区',330200),(330206,'北仑区',330200),(330211,'镇海区',330200),(330212,'鄞州区',330200),(330225,'象山县',330200),(330226,'宁海县',330200),(330281,'余姚市',330200),(330282,'慈溪市',330200),(330283,'奉化市',330200),(330300,'温州市',330000),(330302,'鹿城区',330300),(330303,'龙湾区',330300),(330304,'瓯海区',330300),(330305,'洞头区',330300),(330324,'永嘉县',330300),(330326,'平阳县',330300),(330327,'苍南县',330300),(330328,'文成县',330300),(330329,'泰顺县',330300),(330381,'瑞安市',330300),(330382,'乐清市',330300),(330400,'嘉兴市',330000),(330402,'南湖区',330400),(330411,'秀洲区',330400),(330421,'嘉善县',330400),(330424,'海盐县',330400),(330481,'海宁市',330400),(330482,'平湖市',330400),(330483,'桐乡市',330400),(330500,'湖州市',330000),(330502,'吴兴区',330500),(330503,'南浔区',330500),(330521,'德清县',330500),(330522,'长兴县',330500),(330523,'安吉县',330500),(330600,'绍兴市',330000),(330602,'越城区',330600),(330603,'柯桥区',330600),(330604,'上虞区',330600),(330624,'新昌县',330600),(330681,'诸暨市',330600),(330683,'嵊州市',330600),(330700,'金华市',330000),(330702,'婺城区',330700),(330703,'金东区',330700),(330723,'武义县',330700),(330726,'浦江县',330700),(330727,'磐安县',330700),(330781,'兰溪市',330700),(330782,'义乌市',330700),(330783,'东阳市',330700),(330784,'永康市',330700),(330800,'衢州市',330000),(330802,'柯城区',330800),(330803,'衢江区',330800),(330822,'常山县',330800),(330824,'开化县',330800),(330825,'龙游县',330800),(330881,'江山市',330800),(330900,'舟山市',330000),(330902,'定海区',330900),(330903,'普陀区',330900),(330921,'岱山县',330900),(330922,'嵊泗县',330900),(331000,'台州市',330000),(331002,'椒江区',331000),(331003,'黄岩区',331000),(331004,'路桥区',331000),(331021,'玉环县',331000),(331022,'三门县',331000),(331023,'天台县',331000),(331024,'仙居县',331000),(331081,'温岭市',331000),(331082,'临海市',331000),(331100,'丽水市',330000),(331102,'莲都区',331100),(331121,'青田县',331100),(331122,'缙云县',331100),(331123,'遂昌县',331100),(331124,'松阳县',331100),(331125,'云和县',331100),(331126,'庆元县',331100),(331127,'景宁畲族自治县',331100),(331181,'龙泉市',331100),(340000,'安徽省',NULL),(340100,'合肥市',340000),(340102,'瑶海区',340100),(340103,'庐阳区',340100),(340104,'蜀山区',340100),(340111,'包河区',340100),(340121,'长丰县',340100),(340122,'肥东县',340100),(340123,'肥西县',340100),(340124,'庐江县',340100),(340181,'巢湖市',340100),(340200,'芜湖市',340000),(340202,'镜湖区',340200),(340203,'弋江区',340200),(340207,'鸠江区',340200),(340208,'三山区',340200),(340221,'芜湖县',340200),(340222,'繁昌县',340200),(340223,'南陵县',340200),(340225,'无为县',340200),(340300,'蚌埠市',340000),(340302,'龙子湖区',340300),(340303,'蚌山区',340300),(340304,'禹会区',340300),(340311,'淮上区',340300),(340321,'怀远县',340300),(340322,'五河县',340300),(340323,'固镇县',340300),(340400,'淮南市',340000),(340402,'大通区',340400),(340403,'田家庵区',340400),(340404,'谢家集区',340400),(340405,'八公山区',340400),(340406,'潘集区',340400),(340421,'凤台县',340400),(340422,'寿县',340400),(340500,'马鞍山市',340000),(340503,'花山区',340500),(340504,'雨山区',340500),(340506,'博望区',340500),(340521,'当涂县',340500),(340522,'含山县',340500),(340523,'和县',340500),(340600,'淮北市',340000),(340602,'杜集区',340600),(340603,'相山区',340600),(340604,'烈山区',340600),(340621,'濉溪县',340600),(340700,'铜陵市',340000),(340705,'铜官区',340700),(340706,'义安区',340700),(340711,'郊区',340700),(340722,'枞阳县',340700),(340800,'安庆市',340000),(340802,'迎江区',340800),(340803,'大观区',340800),(340811,'宜秀区',340800),(340822,'怀宁县',340800),(340824,'潜山县',340800),(340825,'太湖县',340800),(340826,'宿松县',340800),(340827,'望江县',340800),(340828,'岳西县',340800),(340881,'桐城市',340800),(341000,'黄山市',340000),(341002,'屯溪区',341000),(341003,'黄山区',341000),(341004,'徽州区',341000),(341021,'歙县',341000),(341022,'休宁县',341000),(341023,'黟县',341000),(341024,'祁门县',341000),(341100,'滁州市',340000),(341102,'琅琊区',341100),(341103,'南谯区',341100),(341122,'来安县',341100),(341124,'全椒县',341100),(341125,'定远县',341100),(341126,'凤阳县',341100),(341181,'天长市',341100),(341182,'明光市',341100),(341200,'阜阳市',340000),(341202,'颍州区',341200),(341203,'颍东区',341200),(341204,'颍泉区',341200),(341221,'临泉县',341200),(341222,'太和县',341200),(341225,'阜南县',341200),(341226,'颍上县',341200),(341282,'界首市',341200),(341300,'宿州市',340000),(341302,'埇桥区',341300),(341321,'砀山县',341300),(341322,'萧县',341300),(341323,'灵璧县',341300),(341324,'泗县',341300),(341500,'六安市',340000),(341502,'金安区',341500),(341503,'裕安区',341500),(341504,'叶集区',341500),(341522,'霍邱县',341500),(341523,'舒城县',341500),(341524,'金寨县',341500),(341525,'霍山县',341500),(341600,'亳州市',340000),(341602,'谯城区',341600),(341621,'涡阳县',341600),(341622,'蒙城县',341600),(341623,'利辛县',341600),(341700,'池州市',340000),(341702,'贵池区',341700),(341721,'东至县',341700),(341722,'石台县',341700),(341723,'青阳县',341700),(341800,'宣城市',340000),(341802,'宣州区',341800),(341821,'郎溪县',341800),(341822,'广德县',341800),(341823,'泾县',341800),(341824,'绩溪县',341800),(341825,'旌德县',341800),(341881,'宁国市',341800),(350000,'福建省',NULL),(350100,'福州市',350000),(350102,'鼓楼区',350100),(350103,'台江区',350100),(350104,'仓山区',350100),(350105,'马尾区',350100),(350111,'晋安区',350100),(350121,'闽侯县',350100),(350122,'连江县',350100),(350123,'罗源县',350100),(350124,'闽清县',350100),(350125,'永泰县',350100),(350128,'平潭县',350100),(350181,'福清市',350100),(350182,'长乐市',350100),(350200,'厦门市',350000),(350203,'思明区',350200),(350205,'海沧区',350200),(350206,'湖里区',350200),(350211,'集美区',350200),(350212,'同安区',350200),(350213,'翔安区',350200),(350300,'莆田市',350000),(350302,'城厢区',350300),(350303,'涵江区',350300),(350304,'荔城区',350300),(350305,'秀屿区',350300),(350322,'仙游县',350300),(350400,'三明市',350000),(350402,'梅列区',350400),(350403,'三元区',350400),(350421,'明溪县',350400),(350423,'清流县',350400),(350424,'宁化县',350400),(350425,'大田县',350400),(350426,'尤溪县',350400),(350427,'沙县',350400),(350428,'将乐县',350400),(350429,'泰宁县',350400),(350430,'建宁县',350400),(350481,'永安市',350400),(350500,'泉州市',350000),(350502,'鲤城区',350500),(350503,'丰泽区',350500),(350504,'洛江区',350500),(350505,'泉港区',350500),(350521,'惠安县',350500),(350524,'安溪县',350500),(350525,'永春县',350500),(350526,'德化县',350500),(350527,'金门县',350500),(350581,'石狮市',350500),(350582,'晋江市',350500),(350583,'南安市',350500),(350600,'漳州市',350000),(350602,'芗城区',350600),(350603,'龙文区',350600),(350622,'云霄县',350600),(350623,'漳浦县',350600),(350624,'诏安县',350600),(350625,'长泰县',350600),(350626,'东山县',350600),(350627,'南靖县',350600),(350628,'平和县',350600),(350629,'华安县',350600),(350681,'龙海市',350600),(350700,'南平市',350000),(350702,'延平区',350700),(350703,'建阳区',350700),(350721,'顺昌县',350700),(350722,'浦城县',350700),(350723,'光泽县',350700),(350724,'松溪县',350700),(350725,'政和县',350700),(350781,'邵武市',350700),(350782,'武夷山市',350700),(350783,'建瓯市',350700),(350800,'龙岩市',350000),(350802,'新罗区',350800),(350803,'永定区',350800),(350821,'长汀县',350800),(350823,'上杭县',350800),(350824,'武平县',350800),(350825,'连城县',350800),(350881,'漳平市',350800),(350900,'宁德市',350000),(350902,'蕉城区',350900),(350921,'霞浦县',350900),(350922,'古田县',350900),(350923,'屏南县',350900),(350924,'寿宁县',350900),(350925,'周宁县',350900),(350926,'柘荣县',350900),(350981,'福安市',350900),(350982,'福鼎市',350900),(360000,'江西省',NULL),(360100,'南昌市',360000),(360102,'东湖区',360100),(360103,'西湖区',360100),(360104,'青云谱区',360100),(360105,'湾里区',360100),(360111,'青山湖区',360100),(360112,'新建区',360100),(360121,'南昌县',360100),(360123,'安义县',360100),(360124,'进贤县',360100),(360200,'景德镇市',360000),(360202,'昌江区',360200),(360203,'珠山区',360200),(360222,'浮梁县',360200),(360281,'乐平市',360200),(360300,'萍乡市',360000),(360302,'安源区',360300),(360313,'湘东区',360300),(360321,'莲花县',360300),(360322,'上栗县',360300),(360323,'芦溪县',360300),(360400,'九江市',360000),(360402,'濂溪区',360400),(360403,'浔阳区',360400),(360421,'九江县',360400),(360423,'武宁县',360400),(360424,'修水县',360400),(360425,'永修县',360400),(360426,'德安县',360400),(360428,'都昌县',360400),(360429,'湖口县',360400),(360430,'彭泽县',360400),(360481,'瑞昌市',360400),(360482,'共青城市',360400),(360483,'庐山市',360400),(360500,'新余市',360000),(360502,'渝水区',360500),(360521,'分宜县',360500),(360600,'鹰潭市',360000),(360602,'月湖区',360600),(360622,'余江县',360600),(360681,'贵溪市',360600),(360700,'赣州市',360000),(360702,'章贡区',360700),(360703,'南康区',360700),(360721,'赣县',360700),(360722,'信丰县',360700),(360723,'大余县',360700),(360724,'上犹县',360700),(360725,'崇义县',360700),(360726,'安远县',360700),(360727,'龙南县',360700),(360728,'定南县',360700),(360729,'全南县',360700),(360730,'宁都县',360700),(360731,'于都县',360700),(360732,'兴国县',360700),(360733,'会昌县',360700),(360734,'寻乌县',360700),(360735,'石城县',360700),(360781,'瑞金市',360700),(360800,'吉安市',360000),(360802,'吉州区',360800),(360803,'青原区',360800),(360821,'吉安县',360800),(360822,'吉水县',360800),(360823,'峡江县',360800),(360824,'新干县',360800),(360825,'永丰县',360800),(360826,'泰和县',360800),(360827,'遂川县',360800),(360828,'万安县',360800),(360829,'安福县',360800),(360830,'永新县',360800),(360881,'井冈山市',360800),(360900,'宜春市',360000),(360902,'袁州区',360900),(360921,'奉新县',360900),(360922,'万载县',360900),(360923,'上高县',360900),(360924,'宜丰县',360900),(360925,'靖安县',360900),(360926,'铜鼓县',360900),(360981,'丰城市',360900),(360982,'樟树市',360900),(360983,'高安市',360900),(361000,'抚州市',360000),(361002,'临川区',361000),(361021,'南城县',361000),(361022,'黎川县',361000),(361023,'南丰县',361000),(361024,'崇仁县',361000),(361025,'乐安县',361000),(361026,'宜黄县',361000),(361027,'金溪县',361000),(361028,'资溪县',361000),(361029,'东乡县',361000),(361030,'广昌县',361000),(361100,'上饶市',360000),(361102,'信州区',361100),(361103,'广丰区',361100),(361121,'上饶县',361100),(361123,'玉山县',361100),(361124,'铅山县',361100),(361125,'横峰县',361100),(361126,'弋阳县',361100),(361127,'余干县',361100),(361128,'鄱阳县',361100),(361129,'万年县',361100),(361130,'婺源县',361100),(361181,'德兴市',361100),(370000,'山东省',NULL),(370100,'济南市',370000),(370102,'历下区',370100),(370103,'市中区',370100),(370104,'槐荫区',370100),(370105,'天桥区',370100),(370112,'历城区',370100),(370113,'长清区',370100),(370124,'平阴县',370100),(370125,'济阳县',370100),(370126,'商河县',370100),(370181,'章丘市',370100),(370200,'青岛市',370000),(370202,'市南区',370200),(370203,'市北区',370200),(370211,'黄岛区',370200),(370212,'崂山区',370200),(370213,'李沧区',370200),(370214,'城阳区',370200),(370281,'胶州市',370200),(370282,'即墨市',370200),(370283,'平度市',370200),(370285,'莱西市',370200),(370300,'淄博市',370000),(370302,'淄川区',370300),(370303,'张店区',370300),(370304,'博山区',370300),(370305,'临淄区',370300),(370306,'周村区',370300),(370321,'桓台县',370300),(370322,'高青县',370300),(370323,'沂源县',370300),(370400,'枣庄市',370000),(370402,'市中区',370400),(370403,'薛城区',370400),(370404,'峄城区',370400),(370405,'台儿庄区',370400),(370406,'山亭区',370400),(370481,'滕州市',370400),(370500,'东营市',370000),(370502,'东营区',370500),(370503,'河口区',370500),(370505,'垦利区',370500),(370522,'利津县',370500),(370523,'广饶县',370500),(370600,'烟台市',370000),(370602,'芝罘区',370600),(370611,'福山区',370600),(370612,'牟平区',370600),(370613,'莱山区',370600),(370634,'长岛县',370600),(370681,'龙口市',370600),(370682,'莱阳市',370600),(370683,'莱州市',370600),(370684,'蓬莱市',370600),(370685,'招远市',370600),(370686,'栖霞市',370600),(370687,'海阳市',370600),(370700,'潍坊市',370000),(370702,'潍城区',370700),(370703,'寒亭区',370700),(370704,'坊子区',370700),(370705,'奎文区',370700),(370724,'临朐县',370700),(370725,'昌乐县',370700),(370781,'青州市',370700),(370782,'诸城市',370700),(370783,'寿光市',370700),(370784,'安丘市',370700),(370785,'高密市',370700),(370786,'昌邑市',370700),(370800,'济宁市',370000),(370811,'任城区',370800),(370812,'兖州区',370800),(370826,'微山县',370800),(370827,'鱼台县',370800),(370828,'金乡县',370800),(370829,'嘉祥县',370800),(370830,'汶上县',370800),(370831,'泗水县',370800),(370832,'梁山县',370800),(370881,'曲阜市',370800),(370883,'邹城市',370800),(370900,'泰安市',370000),(370902,'泰山区',370900),(370911,'岱岳区',370900),(370921,'宁阳县',370900),(370923,'东平县',370900),(370982,'新泰市',370900),(370983,'肥城市',370900),(371000,'威海市',370000),(371002,'环翠区',371000),(371003,'文登区',371000),(371082,'荣成市',371000),(371083,'乳山市',371000),(371100,'日照市',370000),(371102,'东港区',371100),(371103,'岚山区',371100),(371121,'五莲县',371100),(371122,'莒县',371100),(371200,'莱芜市',370000),(371202,'莱城区',371200),(371203,'钢城区',371200),(371300,'临沂市',370000),(371302,'兰山区',371300),(371311,'罗庄区',371300),(371312,'河东区',371300),(371321,'沂南县',371300),(371322,'郯城县',371300),(371323,'沂水县',371300),(371324,'兰陵县',371300),(371325,'费县',371300),(371326,'平邑县',371300),(371327,'莒南县',371300),(371328,'蒙阴县',371300),(371329,'临沭县',371300),(371400,'德州市',370000),(371402,'德城区',371400),(371403,'陵城区',371400),(371422,'宁津县',371400),(371423,'庆云县',371400),(371424,'临邑县',371400),(371425,'齐河县',371400),(371426,'平原县',371400),(371427,'夏津县',371400),(371428,'武城县',371400),(371481,'乐陵市',371400),(371482,'禹城市',371400),(371500,'聊城市',370000),(371502,'东昌府区',371500),(371521,'阳谷县',371500),(371522,'莘县',371500),(371523,'茌平县',371500),(371524,'东阿县',371500),(371525,'冠县',371500),(371526,'高唐县',371500),(371581,'临清市',371500),(371600,'滨州市',370000),(371602,'滨城区',371600),(371603,'沾化区',371600),(371621,'惠民县',371600),(371622,'阳信县',371600),(371623,'无棣县',371600),(371625,'博兴县',371600),(371626,'邹平县',371600),(371700,'菏泽市',370000),(371702,'牡丹区',371700),(371703,'定陶区',371700),(371721,'曹县',371700),(371722,'单县',371700),(371723,'成武县',371700),(371724,'巨野县',371700),(371725,'郓城县',371700),(371726,'鄄城县',371700),(371728,'东明县',371700),(410000,'河南省',NULL),(410100,'郑州市',410000),(410102,'中原区',410100),(410103,'二七区',410100),(410104,'管城回族区',410100),(410105,'金水区',410100),(410106,'上街区',410100),(410108,'惠济区',410100),(410122,'中牟县',410100),(410181,'巩义市',410100),(410182,'荥阳市',410100),(410183,'新密市',410100),(410184,'新郑市',410100),(410185,'登封市',410100),(410200,'开封市',410000),(410202,'龙亭区',410200),(410203,'顺河回族区',410200),(410204,'鼓楼区',410200),(410205,'禹王台区',410200),(410211,'金明区',410200),(410212,'祥符区',410200),(410221,'杞县',410200),(410222,'通许县',410200),(410223,'尉氏县',410200),(410225,'兰考县',410200),(410300,'洛阳市',410000),(410302,'老城区',410300),(410303,'西工区',410300),(410304,'瀍河回族区',410300),(410305,'涧西区',410300),(410306,'吉利区',410300),(410311,'洛龙区',410300),(410322,'孟津县',410300),(410323,'新安县',410300),(410324,'栾川县',410300),(410325,'嵩县',410300),(410326,'汝阳县',410300),(410327,'宜阳县',410300),(410328,'洛宁县',410300),(410329,'伊川县',410300),(410381,'偃师市',410300),(410400,'平顶山市',410000),(410402,'新华区',410400),(410403,'卫东区',410400),(410404,'石龙区',410400),(410411,'湛河区',410400),(410421,'宝丰县',410400),(410422,'叶县',410400),(410423,'鲁山县',410400),(410425,'郏县',410400),(410481,'舞钢市',410400),(410482,'汝州市',410400),(410500,'安阳市',410000),(410502,'文峰区',410500),(410503,'北关区',410500),(410505,'殷都区',410500),(410506,'龙安区',410500),(410522,'安阳县',410500),(410523,'汤阴县',410500),(410526,'滑县',410500),(410527,'内黄县',410500),(410581,'林州市',410500),(410600,'鹤壁市',410000),(410602,'鹤山区',410600),(410603,'山城区',410600),(410611,'淇滨区',410600),(410621,'浚县',410600),(410622,'淇县',410600),(410700,'新乡市',410000),(410702,'红旗区',410700),(410703,'卫滨区',410700),(410704,'凤泉区',410700),(410711,'牧野区',410700),(410721,'新乡县',410700),(410724,'获嘉县',410700),(410725,'原阳县',410700),(410726,'延津县',410700),(410727,'封丘县',410700),(410728,'长垣县',410700),(410781,'卫辉市',410700),(410782,'辉县市',410700),(410800,'焦作市',410000),(410802,'解放区',410800),(410803,'中站区',410800),(410804,'马村区',410800),(410811,'山阳区',410800),(410821,'修武县',410800),(410822,'博爱县',410800),(410823,'武陟县',410800),(410825,'温县',410800),(410882,'沁阳市',410800),(410883,'孟州市',410800),(410900,'濮阳市',410000),(410902,'华龙区',410900),(410922,'清丰县',410900),(410923,'南乐县',410900),(410926,'范县',410900),(410927,'台前县',410900),(410928,'濮阳县',410900),(411000,'许昌市',410000),(411002,'魏都区',411000),(411023,'许昌县',411000),(411024,'鄢陵县',411000),(411025,'襄城县',411000),(411081,'禹州市',411000),(411082,'长葛市',411000),(411100,'漯河市',410000),(411102,'源汇区',411100),(411103,'郾城区',411100),(411104,'召陵区',411100),(411121,'舞阳县',411100),(411122,'临颍县',411100),(411200,'三门峡市',410000),(411202,'湖滨区',411200),(411203,'陕州区',411200),(411221,'渑池县',411200),(411224,'卢氏县',411200),(411281,'义马市',411200),(411282,'灵宝市',411200),(411300,'南阳市',410000),(411302,'宛城区',411300),(411303,'卧龙区',411300),(411321,'南召县',411300),(411322,'方城县',411300),(411323,'西峡县',411300),(411324,'镇平县',411300),(411325,'内乡县',411300),(411326,'淅川县',411300),(411327,'社旗县',411300),(411328,'唐河县',411300),(411329,'新野县',411300),(411330,'桐柏县',411300),(411381,'邓州市',411300),(411400,'商丘市',410000),(411402,'梁园区',411400),(411403,'睢阳区',411400),(411421,'民权县',411400),(411422,'睢县',411400),(411423,'宁陵县',411400),(411424,'柘城县',411400),(411425,'虞城县',411400),(411426,'夏邑县',411400),(411481,'永城市',411400),(411500,'信阳市',410000),(411502,'浉河区',411500),(411503,'平桥区',411500),(411521,'罗山县',411500),(411522,'光山县',411500),(411523,'新县',411500),(411524,'商城县',411500),(411525,'固始县',411500),(411526,'潢川县',411500),(411527,'淮滨县',411500),(411528,'息县',411500),(411600,'周口市',410000),(411602,'川汇区',411600),(411621,'扶沟县',411600),(411622,'西华县',411600),(411623,'商水县',411600),(411624,'沈丘县',411600),(411625,'郸城县',411600),(411626,'淮阳县',411600),(411627,'太康县',411600),(411628,'鹿邑县',411600),(411681,'项城市',411600),(411700,'驻马店市',410000),(411702,'驿城区',411700),(411721,'西平县',411700),(411722,'上蔡县',411700),(411723,'平舆县',411700),(411724,'正阳县',411700),(411725,'确山县',411700),(411726,'泌阳县',411700),(411727,'汝南县',411700),(411728,'遂平县',411700),(411729,'新蔡县',411700),(419000,'省直辖县级行政区划',410000),(419001,'济源市',419000),(420000,'湖北省',NULL),(420100,'武汉市',420000),(420102,'江岸区',420100),(420103,'江汉区',420100),(420104,'硚口区',420100),(420105,'汉阳区',420100),(420106,'武昌区',420100),(420107,'青山区',420100),(420111,'洪山区',420100),(420112,'东西湖区',420100),(420113,'汉南区',420100),(420114,'蔡甸区',420100),(420115,'江夏区',420100),(420116,'黄陂区',420100),(420117,'新洲区',420100),(420200,'黄石市',420000),(420202,'黄石港区',420200),(420203,'西塞山区',420200),(420204,'下陆区',420200),(420205,'铁山区',420200),(420222,'阳新县',420200),(420281,'大冶市',420200),(420300,'十堰市',420000),(420302,'茅箭区',420300),(420303,'张湾区',420300),(420304,'郧阳区',420300),(420322,'郧西县',420300),(420323,'竹山县',420300),(420324,'竹溪县',420300),(420325,'房县',420300),(420381,'丹江口市',420300),(420500,'宜昌市',420000),(420502,'西陵区',420500),(420503,'伍家岗区',420500),(420504,'点军区',420500),(420505,'猇亭区',420500),(420506,'夷陵区',420500),(420525,'远安县',420500),(420526,'兴山县',420500),(420527,'秭归县',420500),(420528,'长阳土家族自治县',420500),(420529,'五峰土家族自治县',420500),(420581,'宜都市',420500),(420582,'当阳市',420500),(420583,'枝江市',420500),(420600,'襄阳市',420000),(420602,'襄城区',420600),(420606,'樊城区',420600),(420607,'襄州区',420600),(420624,'南漳县',420600),(420625,'谷城县',420600),(420626,'保康县',420600),(420682,'老河口市',420600),(420683,'枣阳市',420600),(420684,'宜城市',420600),(420700,'鄂州市',420000),(420702,'梁子湖区',420700),(420703,'华容区',420700),(420704,'鄂城区',420700),(420800,'荆门市',420000),(420802,'东宝区',420800),(420804,'掇刀区',420800),(420821,'京山县',420800),(420822,'沙洋县',420800),(420881,'钟祥市',420800),(420900,'孝感市',420000),(420902,'孝南区',420900),(420921,'孝昌县',420900),(420922,'大悟县',420900),(420923,'云梦县',420900),(420981,'应城市',420900),(420982,'安陆市',420900),(420984,'汉川市',420900),(421000,'荆州市',420000),(421002,'沙市区',421000),(421003,'荆州区',421000),(421022,'公安县',421000),(421023,'监利县',421000),(421024,'江陵县',421000),(421081,'石首市',421000),(421083,'洪湖市',421000),(421087,'松滋市',421000),(421100,'黄冈市',420000),(421102,'黄州区',421100),(421121,'团风县',421100),(421122,'红安县',421100),(421123,'罗田县',421100),(421124,'英山县',421100),(421125,'浠水县',421100),(421126,'蕲春县',421100),(421127,'黄梅县',421100),(421181,'麻城市',421100),(421182,'武穴市',421100),(421200,'咸宁市',420000),(421202,'咸安区',421200),(421221,'嘉鱼县',421200),(421222,'通城县',421200),(421223,'崇阳县',421200),(421224,'通山县',421200),(421281,'赤壁市',421200),(421300,'随州市',420000),(421303,'曾都区',421300),(421321,'随县',421300),(421381,'广水市',421300),(422800,'恩施土家族苗族自治州',420000),(422801,'恩施市',422800),(422802,'利川市',422800),(422822,'建始县',422800),(422823,'巴东县',422800),(422825,'宣恩县',422800),(422826,'咸丰县',422800),(422827,'来凤县',422800),(422828,'鹤峰县',422800),(429000,'省直辖县级行政区划',420000),(429004,'仙桃市',429000),(429005,'潜江市',429000),(429006,'天门市',429000),(429021,'神农架林区',429000),(430000,'湖南省',NULL),(430100,'长沙市',430000),(430102,'芙蓉区',430100),(430103,'天心区',430100),(430104,'岳麓区',430100),(430105,'开福区',430100),(430111,'雨花区',430100),(430112,'望城区',430100),(430121,'长沙县',430100),(430124,'宁乡县',430100),(430181,'浏阳市',430100),(430200,'株洲市',430000),(430202,'荷塘区',430200),(430203,'芦淞区',430200),(430204,'石峰区',430200),(430211,'天元区',430200),(430221,'株洲县',430200),(430223,'攸县',430200),(430224,'茶陵县',430200),(430225,'炎陵县',430200),(430281,'醴陵市',430200),(430300,'湘潭市',430000),(430302,'雨湖区',430300),(430304,'岳塘区',430300),(430321,'湘潭县',430300),(430381,'湘乡市',430300),(430382,'韶山市',430300),(430400,'衡阳市',430000),(430405,'珠晖区',430400),(430406,'雁峰区',430400),(430407,'石鼓区',430400),(430408,'蒸湘区',430400),(430412,'南岳区',430400),(430421,'衡阳县',430400),(430422,'衡南县',430400),(430423,'衡山县',430400),(430424,'衡东县',430400),(430426,'祁东县',430400),(430481,'耒阳市',430400),(430482,'常宁市',430400),(430500,'邵阳市',430000),(430502,'双清区',430500),(430503,'大祥区',430500),(430511,'北塔区',430500),(430521,'邵东县',430500),(430522,'新邵县',430500),(430523,'邵阳县',430500),(430524,'隆回县',430500),(430525,'洞口县',430500),(430527,'绥宁县',430500),(430528,'新宁县',430500),(430529,'城步苗族自治县',430500),(430581,'武冈市',430500),(430600,'岳阳市',430000),(430602,'岳阳楼区',430600),(430603,'云溪区',430600),(430611,'君山区',430600),(430621,'岳阳县',430600),(430623,'华容县',430600),(430624,'湘阴县',430600),(430626,'平江县',430600),(430681,'汨罗市',430600),(430682,'临湘市',430600),(430700,'常德市',430000),(430702,'武陵区',430700),(430703,'鼎城区',430700),(430721,'安乡县',430700),(430722,'汉寿县',430700),(430723,'澧县',430700),(430724,'临澧县',430700),(430725,'桃源县',430700),(430726,'石门县',430700),(430781,'津市市',430700),(430800,'张家界市',430000),(430802,'永定区',430800),(430811,'武陵源区',430800),(430821,'慈利县',430800),(430822,'桑植县',430800),(430900,'益阳市',430000),(430902,'资阳区',430900),(430903,'赫山区',430900),(430921,'南县',430900),(430922,'桃江县',430900),(430923,'安化县',430900),(430981,'沅江市',430900),(431000,'郴州市',430000),(431002,'北湖区',431000),(431003,'苏仙区',431000),(431021,'桂阳县',431000),(431022,'宜章县',431000),(431023,'永兴县',431000),(431024,'嘉禾县',431000),(431025,'临武县',431000),(431026,'汝城县',431000),(431027,'桂东县',431000),(431028,'安仁县',431000),(431081,'资兴市',431000),(431100,'永州市',430000),(431102,'零陵区',431100),(431103,'冷水滩区',431100),(431121,'祁阳县',431100),(431122,'东安县',431100),(431123,'双牌县',431100),(431124,'道县',431100),(431125,'江永县',431100),(431126,'宁远县',431100),(431127,'蓝山县',431100),(431128,'新田县',431100),(431129,'江华瑶族自治县',431100),(431200,'怀化市',430000),(431202,'鹤城区',431200),(431221,'中方县',431200),(431222,'沅陵县',431200),(431223,'辰溪县',431200),(431224,'溆浦县',431200),(431225,'会同县',431200),(431226,'麻阳苗族自治县',431200),(431227,'新晃侗族自治县',431200),(431228,'芷江侗族自治县',431200),(431229,'靖州苗族侗族自治县',431200),(431230,'通道侗族自治县',431200),(431281,'洪江市',431200),(431300,'娄底市',430000),(431302,'娄星区',431300),(431321,'双峰县',431300),(431322,'新化县',431300),(431381,'冷水江市',431300),(431382,'涟源市',431300),(433100,'湘西土家族苗族自治州',430000),(433101,'吉首市',433100),(433122,'泸溪县',433100),(433123,'凤凰县',433100),(433124,'花垣县',433100),(433125,'保靖县',433100),(433126,'古丈县',433100),(433127,'永顺县',433100),(433130,'龙山县',433100),(440000,'广东省',NULL),(440100,'广州市',440000),(440103,'荔湾区',440100),(440104,'越秀区',440100),(440105,'海珠区',440100),(440106,'天河区',440100),(440111,'白云区',440100),(440112,'黄埔区',440100),(440113,'番禺区',440100),(440114,'花都区',440100),(440115,'南沙区',440100),(440117,'从化区',440100),(440118,'增城区',440100),(440200,'韶关市',440000),(440203,'武江区',440200),(440204,'浈江区',440200),(440205,'曲江区',440200),(440222,'始兴县',440200),(440224,'仁化县',440200),(440229,'翁源县',440200),(440232,'乳源瑶族自治县',440200),(440233,'新丰县',440200),(440281,'乐昌市',440200),(440282,'南雄市',440200),(440300,'深圳市',440000),(440303,'罗湖区',440300),(440304,'福田区',440300),(440305,'南山区',440300),(440306,'宝安区',440300),(440307,'龙岗区',440300),(440308,'盐田区',440300),(440400,'珠海市',440000),(440402,'香洲区',440400),(440403,'斗门区',440400),(440404,'金湾区',440400),(440500,'汕头市',440000),(440507,'龙湖区',440500),(440511,'金平区',440500),(440512,'濠江区',440500),(440513,'潮阳区',440500),(440514,'潮南区',440500),(440515,'澄海区',440500),(440523,'南澳县',440500),(440600,'佛山市',440000),(440604,'禅城区',440600),(440605,'南海区',440600),(440606,'顺德区',440600),(440607,'三水区',440600),(440608,'高明区',440600),(440700,'江门市',440000),(440703,'蓬江区',440700),(440704,'江海区',440700),(440705,'新会区',440700),(440781,'台山市',440700),(440783,'开平市',440700),(440784,'鹤山市',440700),(440785,'恩平市',440700),(440800,'湛江市',440000),(440802,'赤坎区',440800),(440803,'霞山区',440800),(440804,'坡头区',440800),(440811,'麻章区',440800),(440823,'遂溪县',440800),(440825,'徐闻县',440800),(440881,'廉江市',440800),(440882,'雷州市',440800),(440883,'吴川市',440800),(440900,'茂名市',440000),(440902,'茂南区',440900),(440904,'电白区',440900),(440981,'高州市',440900),(440982,'化州市',440900),(440983,'信宜市',440900),(441200,'肇庆市',440000),(441202,'端州区',441200),(441203,'鼎湖区',441200),(441204,'高要区',441200),(441223,'广宁县',441200),(441224,'怀集县',441200),(441225,'封开县',441200),(441226,'德庆县',441200),(441284,'四会市',441200),(441300,'惠州市',440000),(441302,'惠城区',441300),(441303,'惠阳区',441300),(441322,'博罗县',441300),(441323,'惠东县',441300),(441324,'龙门县',441300),(441400,'梅州市',440000),(441402,'梅江区',441400),(441403,'梅县区',441400),(441422,'大埔县',441400),(441423,'丰顺县',441400),(441424,'五华县',441400),(441426,'平远县',441400),(441427,'蕉岭县',441400),(441481,'兴宁市',441400),(441500,'汕尾市',440000),(441502,'城区',441500),(441521,'海丰县',441500),(441523,'陆河县',441500),(441581,'陆丰市',441500),(441600,'河源市',440000),(441602,'源城区',441600),(441621,'紫金县',441600),(441622,'龙川县',441600),(441623,'连平县',441600),(441624,'和平县',441600),(441625,'东源县',441600),(441700,'阳江市',440000),(441702,'江城区',441700),(441704,'阳东区',441700),(441721,'阳西县',441700),(441781,'阳春市',441700),(441800,'清远市',440000),(441802,'清城区',441800),(441803,'清新区',441800),(441821,'佛冈县',441800),(441823,'阳山县',441800),(441825,'连山壮族瑶族自治县',441800),(441826,'连南瑶族自治县',441800),(441881,'英德市',441800),(441882,'连州市',441800),(441900,'东莞市',440000),(442000,'中山市',440000),(445100,'潮州市',440000),(445102,'湘桥区',445100),(445103,'潮安区',445100),(445122,'饶平县',445100),(445200,'揭阳市',440000),(445202,'榕城区',445200),(445203,'揭东区',445200),(445222,'揭西县',445200),(445224,'惠来县',445200),(445281,'普宁市',445200),(445300,'云浮市',440000),(445302,'云城区',445300),(445303,'云安区',445300),(445321,'新兴县',445300),(445322,'郁南县',445300),(445381,'罗定市',445300),(450000,'广西壮族自治区',NULL),(450100,'南宁市',450000),(450102,'兴宁区',450100),(450103,'青秀区',450100),(450105,'江南区',450100),(450107,'西乡塘区',450100),(450108,'良庆区',450100),(450109,'邕宁区',450100),(450110,'武鸣区',450100),(450123,'隆安县',450100),(450124,'马山县',450100),(450125,'上林县',450100),(450126,'宾阳县',450100),(450127,'横县',450100),(450200,'柳州市',450000),(450202,'城中区',450200),(450203,'鱼峰区',450200),(450204,'柳南区',450200),(450205,'柳北区',450200),(450206,'柳江区',450200),(450222,'柳城县',450200),(450223,'鹿寨县',450200),(450224,'融安县',450200),(450225,'融水苗族自治县',450200),(450226,'三江侗族自治县',450200),(450300,'桂林市',450000),(450302,'秀峰区',450300),(450303,'叠彩区',450300),(450304,'象山区',450300),(450305,'七星区',450300),(450311,'雁山区',450300),(450312,'临桂区',450300),(450321,'阳朔县',450300),(450323,'灵川县',450300),(450324,'全州县',450300),(450325,'兴安县',450300),(450326,'永福县',450300),(450327,'灌阳县',450300),(450328,'龙胜各族自治县',450300),(450329,'资源县',450300),(450330,'平乐县',450300),(450331,'荔浦县',450300),(450332,'恭城瑶族自治县',450300),(450400,'梧州市',450000),(450403,'万秀区',450400),(450405,'长洲区',450400),(450406,'龙圩区',450400),(450421,'苍梧县',450400),(450422,'藤县',450400),(450423,'蒙山县',450400),(450481,'岑溪市',450400),(450500,'北海市',450000),(450502,'海城区',450500),(450503,'银海区',450500),(450512,'铁山港区',450500),(450521,'合浦县',450500),(450600,'防城港市',450000),(450602,'港口区',450600),(450603,'防城区',450600),(450621,'上思县',450600),(450681,'东兴市',450600),(450700,'钦州市',450000),(450702,'钦南区',450700),(450703,'钦北区',450700),(450721,'灵山县',450700),(450722,'浦北县',450700),(450800,'贵港市',450000),(450802,'港北区',450800),(450803,'港南区',450800),(450804,'覃塘区',450800),(450821,'平南县',450800),(450881,'桂平市',450800),(450900,'玉林市',450000),(450902,'玉州区',450900),(450903,'福绵区',450900),(450921,'容县',450900),(450922,'陆川县',450900),(450923,'博白县',450900),(450924,'兴业县',450900),(450981,'北流市',450900),(451000,'百色市',450000),(451002,'右江区',451000),(451021,'田阳县',451000),(451022,'田东县',451000),(451023,'平果县',451000),(451024,'德保县',451000),(451026,'那坡县',451000),(451027,'凌云县',451000),(451028,'乐业县',451000),(451029,'田林县',451000),(451030,'西林县',451000),(451031,'隆林各族自治县',451000),(451081,'靖西市',451000),(451100,'贺州市',450000),(451102,'八步区',451100),(451103,'平桂区',451100),(451121,'昭平县',451100),(451122,'钟山县',451100),(451123,'富川瑶族自治县',451100),(451200,'河池市',450000),(451202,'金城江区',451200),(451221,'南丹县',451200),(451222,'天峨县',451200),(451223,'凤山县',451200),(451224,'东兰县',451200),(451225,'罗城仫佬族自治县',451200),(451226,'环江毛南族自治县',451200),(451227,'巴马瑶族自治县',451200),(451228,'都安瑶族自治县',451200),(451229,'大化瑶族自治县',451200),(451281,'宜州市',451200),(451300,'来宾市',450000),(451302,'兴宾区',451300),(451321,'忻城县',451300),(451322,'象州县',451300),(451323,'武宣县',451300),(451324,'金秀瑶族自治县',451300),(451381,'合山市',451300),(451400,'崇左市',450000),(451402,'江州区',451400),(451421,'扶绥县',451400),(451422,'宁明县',451400),(451423,'龙州县',451400),(451424,'大新县',451400),(451425,'天等县',451400),(451481,'凭祥市',451400),(460000,'海南省',NULL),(460100,'海口市',460000),(460105,'秀英区',460100),(460106,'龙华区',460100),(460107,'琼山区',460100),(460108,'美兰区',460100),(460200,'三亚市',460000),(460202,'海棠区',460200),(460203,'吉阳区',460200),(460204,'天涯区',460200),(460205,'崖州区',460200),(460300,'三沙市',460000),(460400,'儋州市',460000),(469000,'省直辖县级行政区划',460000),(469001,'五指山市',469000),(469002,'琼海市',469000),(469005,'文昌市',469000),(469006,'万宁市',469000),(469007,'东方市',469000),(469021,'定安县',469000),(469022,'屯昌县',469000),(469023,'澄迈县',469000),(469024,'临高县',469000),(469025,'白沙黎族自治县',469000),(469026,'昌江黎族自治县',469000),(469027,'乐东黎族自治县',469000),(469028,'陵水黎族自治县',469000),(469029,'保亭黎族苗族自治县',469000),(469030,'琼中黎族苗族自治县',469000),(500000,'重庆市',NULL),(500100,'重庆市',500000),(500101,'万州区',500100),(500102,'涪陵区',500100),(500103,'渝中区',500100),(500104,'大渡口区',500100),(500105,'江北区',500100),(500106,'沙坪坝区',500100),(500107,'九龙坡区',500100),(500108,'南岸区',500100),(500109,'北碚区',500100),(500110,'綦江区',500100),(500111,'大足区',500100),(500112,'渝北区',500100),(500113,'巴南区',500100),(500114,'黔江区',500100),(500115,'长寿区',500100),(500116,'江津区',500100),(500117,'合川区',500100),(500118,'永川区',500100),(500119,'南川区',500100),(500120,'璧山区',500100),(500151,'铜梁区',500100),(500152,'潼南区',500100),(500153,'荣昌区',500100),(500154,'开州区',500100),(500200,'县',500000),(500228,'梁平县',500200),(500229,'城口县',500200),(500230,'丰都县',500200),(500231,'垫江县',500200),(500232,'武隆县',500200),(500233,'忠县',500200),(500235,'云阳县',500200),(500236,'奉节县',500200),(500237,'巫山县',500200),(500238,'巫溪县',500200),(500240,'石柱土家族自治县',500200),(500241,'秀山土家族苗族自治县',500200),(500242,'酉阳土家族苗族自治县',500200),(500243,'彭水苗族土家族自治县',500200),(510000,'四川省',NULL),(510100,'成都市',510000),(510104,'锦江区',510100),(510105,'青羊区',510100),(510106,'金牛区',510100),(510107,'武侯区',510100),(510108,'成华区',510100),(510112,'龙泉驿区',510100),(510113,'青白江区',510100),(510114,'新都区',510100),(510115,'温江区',510100),(510116,'双流区',510100),(510121,'金堂县',510100),(510124,'郫县',510100),(510129,'大邑县',510100),(510131,'蒲江县',510100),(510132,'新津县',510100),(510181,'都江堰市',510100),(510182,'彭州市',510100),(510183,'邛崃市',510100),(510184,'崇州市',510100),(510185,'简阳市',510100),(510300,'自贡市',510000),(510302,'自流井区',510300),(510303,'贡井区',510300),(510304,'大安区',510300),(510311,'沿滩区',510300),(510321,'荣县',510300),(510322,'富顺县',510300),(510400,'攀枝花市',510000),(510402,'东区',510400),(510403,'西区',510400),(510411,'仁和区',510400),(510421,'米易县',510400),(510422,'盐边县',510400),(510500,'泸州市',510000),(510502,'江阳区',510500),(510503,'纳溪区',510500),(510504,'龙马潭区',510500),(510521,'泸县',510500),(510522,'合江县',510500),(510524,'叙永县',510500),(510525,'古蔺县',510500),(510600,'德阳市',510000),(510603,'旌阳区',510600),(510623,'中江县',510600),(510626,'罗江县',510600),(510681,'广汉市',510600),(510682,'什邡市',510600),(510683,'绵竹市',510600),(510700,'绵阳市',510000),(510703,'涪城区',510700),(510704,'游仙区',510700),(510705,'安州区',510700),(510722,'三台县',510700),(510723,'盐亭县',510700),(510725,'梓潼县',510700),(510726,'北川羌族自治县',510700),(510727,'平武县',510700),(510781,'江油市',510700),(510800,'广元市',510000),(510802,'利州区',510800),(510811,'昭化区',510800),(510812,'朝天区',510800),(510821,'旺苍县',510800),(510822,'青川县',510800),(510823,'剑阁县',510800),(510824,'苍溪县',510800),(510900,'遂宁市',510000),(510903,'船山区',510900),(510904,'安居区',510900),(510921,'蓬溪县',510900),(510922,'射洪县',510900),(510923,'大英县',510900),(511000,'内江市',510000),(511002,'市中区',511000),(511011,'东兴区',511000),(511024,'威远县',511000),(511025,'资中县',511000),(511028,'隆昌县',511000),(511100,'乐山市',510000),(511102,'市中区',511100),(511111,'沙湾区',511100),(511112,'五通桥区',511100),(511113,'金口河区',511100),(511123,'犍为县',511100),(511124,'井研县',511100),(511126,'夹江县',511100),(511129,'沐川县',511100),(511132,'峨边彝族自治县',511100),(511133,'马边彝族自治县',511100),(511181,'峨眉山市',511100),(511300,'南充市',510000),(511302,'顺庆区',511300),(511303,'高坪区',511300),(511304,'嘉陵区',511300),(511321,'南部县',511300),(511322,'营山县',511300),(511323,'蓬安县',511300),(511324,'仪陇县',511300),(511325,'西充县',511300),(511381,'阆中市',511300),(511400,'眉山市',510000),(511402,'东坡区',511400),(511403,'彭山区',511400),(511421,'仁寿县',511400),(511423,'洪雅县',511400),(511424,'丹棱县',511400),(511425,'青神县',511400),(511500,'宜宾市',510000),(511502,'翠屏区',511500),(511503,'南溪区',511500),(511521,'宜宾县',511500),(511523,'江安县',511500),(511524,'长宁县',511500),(511525,'高县',511500),(511526,'珙县',511500),(511527,'筠连县',511500),(511528,'兴文县',511500),(511529,'屏山县',511500),(511600,'广安市',510000),(511602,'广安区',511600),(511603,'前锋区',511600),(511621,'岳池县',511600),(511622,'武胜县',511600),(511623,'邻水县',511600),(511681,'华蓥市',511600),(511700,'达州市',510000),(511702,'通川区',511700),(511703,'达川区',511700),(511722,'宣汉县',511700),(511723,'开江县',511700),(511724,'大竹县',511700),(511725,'渠县',511700),(511781,'万源市',511700),(511800,'雅安市',510000),(511802,'雨城区',511800),(511803,'名山区',511800),(511822,'荥经县',511800),(511823,'汉源县',511800),(511824,'石棉县',511800),(511825,'天全县',511800),(511826,'芦山县',511800),(511827,'宝兴县',511800),(511900,'巴中市',510000),(511902,'巴州区',511900),(511903,'恩阳区',511900),(511921,'通江县',511900),(511922,'南江县',511900),(511923,'平昌县',511900),(512000,'资阳市',510000),(512002,'雁江区',512000),(512021,'安岳县',512000),(512022,'乐至县',512000),(513200,'阿坝藏族羌族自治州',510000),(513201,'马尔康市',513200),(513221,'汶川县',513200),(513222,'理县',513200),(513223,'茂县',513200),(513224,'松潘县',513200),(513225,'九寨沟县',513200),(513226,'金川县',513200),(513227,'小金县',513200),(513228,'黑水县',513200),(513230,'壤塘县',513200),(513231,'阿坝县',513200),(513232,'若尔盖县',513200),(513233,'红原县',513200),(513300,'甘孜藏族自治州',510000),(513301,'康定市',513300),(513322,'泸定县',513300),(513323,'丹巴县',513300),(513324,'九龙县',513300),(513325,'雅江县',513300),(513326,'道孚县',513300),(513327,'炉霍县',513300),(513328,'甘孜县',513300),(513329,'新龙县',513300),(513330,'德格县',513300),(513331,'白玉县',513300),(513332,'石渠县',513300),(513333,'色达县',513300),(513334,'理塘县',513300),(513335,'巴塘县',513300),(513336,'乡城县',513300),(513337,'稻城县',513300),(513338,'得荣县',513300),(513400,'凉山彝族自治州',510000),(513401,'西昌市',513400),(513422,'木里藏族自治县',513400),(513423,'盐源县',513400),(513424,'德昌县',513400),(513425,'会理县',513400),(513426,'会东县',513400),(513427,'宁南县',513400),(513428,'普格县',513400),(513429,'布拖县',513400),(513430,'金阳县',513400),(513431,'昭觉县',513400),(513432,'喜德县',513400),(513433,'冕宁县',513400),(513434,'越西县',513400),(513435,'甘洛县',513400),(513436,'美姑县',513400),(513437,'雷波县',513400),(520000,'贵州省',NULL),(520100,'贵阳市',520000),(520102,'南明区',520100),(520103,'云岩区',520100),(520111,'花溪区',520100),(520112,'乌当区',520100),(520113,'白云区',520100),(520115,'观山湖区',520100),(520121,'开阳县',520100),(520122,'息烽县',520100),(520123,'修文县',520100),(520181,'清镇市',520100),(520200,'六盘水市',520000),(520201,'钟山区',520200),(520203,'六枝特区',520200),(520221,'水城县',520200),(520222,'盘县',520200),(520300,'遵义市',520000),(520302,'红花岗区',520300),(520303,'汇川区',520300),(520304,'播州区',520300),(520322,'桐梓县',520300),(520323,'绥阳县',520300),(520324,'正安县',520300),(520325,'道真仡佬族苗族自治县',520300),(520326,'务川仡佬族苗族自治县',520300),(520327,'凤冈县',520300),(520328,'湄潭县',520300),(520329,'余庆县',520300),(520330,'习水县',520300),(520381,'赤水市',520300),(520382,'仁怀市',520300),(520400,'安顺市',520000),(520402,'西秀区',520400),(520403,'平坝区',520400),(520422,'普定县',520400),(520423,'镇宁布依族苗族自治县',520400),(520424,'关岭布依族苗族自治县',520400),(520425,'紫云苗族布依族自治县',520400),(520500,'毕节市',520000),(520502,'七星关区',520500),(520521,'大方县',520500),(520522,'黔西县',520500),(520523,'金沙县',520500),(520524,'织金县',520500),(520525,'纳雍县',520500),(520526,'威宁彝族回族苗族自治县',520500),(520527,'赫章县',520500),(520600,'铜仁市',520000),(520602,'碧江区',520600),(520603,'万山区',520600),(520621,'江口县',520600),(520622,'玉屏侗族自治县',520600),(520623,'石阡县',520600),(520624,'思南县',520600),(520625,'印江土家族苗族自治县',520600),(520626,'德江县',520600),(520627,'沿河土家族自治县',520600),(520628,'松桃苗族自治县',520600),(522300,'黔西南布依族苗族自治州',520000),(522301,'兴义市',522300),(522322,'兴仁县',522300),(522323,'普安县',522300),(522324,'晴隆县',522300),(522325,'贞丰县',522300),(522326,'望谟县',522300),(522327,'册亨县',522300),(522328,'安龙县',522300),(522600,'黔东南苗族侗族自治州',520000),(522601,'凯里市',522600),(522622,'黄平县',522600),(522623,'施秉县',522600),(522624,'三穗县',522600),(522625,'镇远县',522600),(522626,'岑巩县',522600),(522627,'天柱县',522600),(522628,'锦屏县',522600),(522629,'剑河县',522600),(522630,'台江县',522600),(522631,'黎平县',522600),(522632,'榕江县',522600),(522633,'从江县',522600),(522634,'雷山县',522600),(522635,'麻江县',522600),(522636,'丹寨县',522600),(522700,'黔南布依族苗族自治州',520000),(522701,'都匀市',522700),(522702,'福泉市',522700),(522722,'荔波县',522700),(522723,'贵定县',522700),(522725,'瓮安县',522700),(522726,'独山县',522700),(522727,'平塘县',522700),(522728,'罗甸县',522700),(522729,'长顺县',522700),(522730,'龙里县',522700),(522731,'惠水县',522700),(522732,'三都水族自治县',522700),(530000,'云南省',NULL),(530100,'昆明市',530000),(530102,'五华区',530100),(530103,'盘龙区',530100),(530111,'官渡区',530100),(530112,'西山区',530100),(530113,'东川区',530100),(530114,'呈贡区',530100),(530122,'晋宁县',530100),(530124,'富民县',530100),(530125,'宜良县',530100),(530126,'石林彝族自治县',530100),(530127,'嵩明县',530100),(530128,'禄劝彝族苗族自治县',530100),(530129,'寻甸回族彝族自治县',530100),(530181,'安宁市',530100),(530300,'曲靖市',530000),(530302,'麒麟区',530300),(530303,'沾益区',530300),(530321,'马龙县',530300),(530322,'陆良县',530300),(530323,'师宗县',530300),(530324,'罗平县',530300),(530325,'富源县',530300),(530326,'会泽县',530300),(530381,'宣威市',530300),(530400,'玉溪市',530000),(530402,'红塔区',530400),(530403,'江川区',530400),(530422,'澄江县',530400),(530423,'通海县',530400),(530424,'华宁县',530400),(530425,'易门县',530400),(530426,'峨山彝族自治县',530400),(530427,'新平彝族傣族自治县',530400),(530428,'元江哈尼族彝族傣族自治县',530400),(530500,'保山市',530000),(530502,'隆阳区',530500),(530521,'施甸县',530500),(530523,'龙陵县',530500),(530524,'昌宁县',530500),(530581,'腾冲市',530500),(530600,'昭通市',530000),(530602,'昭阳区',530600),(530621,'鲁甸县',530600),(530622,'巧家县',530600),(530623,'盐津县',530600),(530624,'大关县',530600),(530625,'永善县',530600),(530626,'绥江县',530600),(530627,'镇雄县',530600),(530628,'彝良县',530600),(530629,'威信县',530600),(530630,'水富县',530600),(530700,'丽江市',530000),(530702,'古城区',530700),(530721,'玉龙纳西族自治县',530700),(530722,'永胜县',530700),(530723,'华坪县',530700),(530724,'宁蒗彝族自治县',530700),(530800,'普洱市',530000),(530802,'思茅区',530800),(530821,'宁洱哈尼族彝族自治县',530800),(530822,'墨江哈尼族自治县',530800),(530823,'景东彝族自治县',530800),(530824,'景谷傣族彝族自治县',530800),(530825,'镇沅彝族哈尼族拉祜族自治县',530800),(530826,'江城哈尼族彝族自治县',530800),(530827,'孟连傣族拉祜族佤族自治县',530800),(530828,'澜沧拉祜族自治县',530800),(530829,'西盟佤族自治县',530800),(530900,'临沧市',530000),(530902,'临翔区',530900),(530921,'凤庆县',530900),(530922,'云县',530900),(530923,'永德县',530900),(530924,'镇康县',530900),(530925,'双江拉祜族佤族布朗族傣族自治县',530900),(530926,'耿马傣族佤族自治县',530900),(530927,'沧源佤族自治县',530900),(532300,'楚雄彝族自治州',530000),(532301,'楚雄市',532300),(532322,'双柏县',532300),(532323,'牟定县',532300),(532324,'南华县',532300),(532325,'姚安县',532300),(532326,'大姚县',532300),(532327,'永仁县',532300),(532328,'元谋县',532300),(532329,'武定县',532300),(532331,'禄丰县',532300),(532500,'红河哈尼族彝族自治州',530000),(532501,'个旧市',532500),(532502,'开远市',532500),(532503,'蒙自市',532500),(532504,'弥勒市',532500),(532523,'屏边苗族自治县',532500),(532524,'建水县',532500),(532525,'石屏县',532500),(532527,'泸西县',532500),(532528,'元阳县',532500),(532529,'红河县',532500),(532530,'金平苗族瑶族傣族自治县',532500),(532531,'绿春县',532500),(532532,'河口瑶族自治县',532500),(532600,'文山壮族苗族自治州',530000),(532601,'文山市',532600),(532622,'砚山县',532600),(532623,'西畴县',532600),(532624,'麻栗坡县',532600),(532625,'马关县',532600),(532626,'丘北县',532600),(532627,'广南县',532600),(532628,'富宁县',532600),(532800,'西双版纳傣族自治州',530000),(532801,'景洪市',532800),(532822,'勐海县',532800),(532823,'勐腊县',532800),(532900,'大理白族自治州',530000),(532901,'大理市',532900),(532922,'漾濞彝族自治县',532900),(532923,'祥云县',532900),(532924,'宾川县',532900),(532925,'弥渡县',532900),(532926,'南涧彝族自治县',532900),(532927,'巍山彝族回族自治县',532900),(532928,'永平县',532900),(532929,'云龙县',532900),(532930,'洱源县',532900),(532931,'剑川县',532900),(532932,'鹤庆县',532900),(533100,'德宏傣族景颇族自治州',530000),(533102,'瑞丽市',533100),(533103,'芒市',533100),(533122,'梁河县',533100),(533123,'盈江县',533100),(533124,'陇川县',533100),(533300,'怒江傈僳族自治州',530000),(533301,'泸水市',533300),(533323,'福贡县',533300),(533324,'贡山独龙族怒族自治县',533300),(533325,'兰坪白族普米族自治县',533300),(533400,'迪庆藏族自治州',530000),(533401,'香格里拉市',533400),(533422,'德钦县',533400),(533423,'维西傈僳族自治县',533400),(540000,'西藏自治区',NULL),(540100,'拉萨市',540000),(540102,'城关区',540100),(540103,'堆龙德庆区',540100),(540121,'林周县',540100),(540122,'当雄县',540100),(540123,'尼木县',540100),(540124,'曲水县',540100),(540126,'达孜县',540100),(540127,'墨竹工卡县',540100),(540200,'日喀则市',540000),(540202,'桑珠孜区',540200),(540221,'南木林县',540200),(540222,'江孜县',540200),(540223,'定日县',540200),(540224,'萨迦县',540200),(540225,'拉孜县',540200),(540226,'昂仁县',540200),(540227,'谢通门县',540200),(540228,'白朗县',540200),(540229,'仁布县',540200),(540230,'康马县',540200),(540231,'定结县',540200),(540232,'仲巴县',540200),(540233,'亚东县',540200),(540234,'吉隆县',540200),(540235,'聂拉木县',540200),(540236,'萨嘎县',540200),(540237,'岗巴县',540200),(540300,'昌都市',540000),(540302,'卡若区',540300),(540321,'江达县',540300),(540322,'贡觉县',540300),(540323,'类乌齐县',540300),(540324,'丁青县',540300),(540325,'察雅县',540300),(540326,'八宿县',540300),(540327,'左贡县',540300),(540328,'芒康县',540300),(540329,'洛隆县',540300),(540330,'边坝县',540300),(540400,'林芝市',540000),(540402,'巴宜区',540400),(540421,'工布江达县',540400),(540422,'米林县',540400),(540423,'墨脱县',540400),(540424,'波密县',540400),(540425,'察隅县',540400),(540426,'朗县',540400),(540500,'山南市',540000),(540502,'乃东区',540500),(540521,'扎囊县',540500),(540522,'贡嘎县',540500),(540523,'桑日县',540500),(540524,'琼结县',540500),(540525,'曲松县',540500),(540526,'措美县',540500),(540527,'洛扎县',540500),(540528,'加查县',540500),(540529,'隆子县',540500),(540530,'错那县',540500),(540531,'浪卡子县',540500),(542400,'那曲地区',540000),(542421,'那曲县',542400),(542422,'嘉黎县',542400),(542423,'比如县',542400),(542424,'聂荣县',542400),(542425,'安多县',542400),(542426,'申扎县',542400),(542427,'索县',542400),(542428,'班戈县',542400),(542429,'巴青县',542400),(542430,'尼玛县',542400),(542431,'双湖县',542400),(542500,'阿里地区',540000),(542521,'普兰县',542500),(542522,'札达县',542500),(542523,'噶尔县',542500),(542524,'日土县',542500),(542525,'革吉县',542500),(542526,'改则县',542500),(542527,'措勤县',542500),(610000,'陕西省',NULL),(610100,'西安市',610000),(610102,'新城区',610100),(610103,'碑林区',610100),(610104,'莲湖区',610100),(610111,'灞桥区',610100),(610112,'未央区',610100),(610113,'雁塔区',610100),(610114,'阎良区',610100),(610115,'临潼区',610100),(610116,'长安区',610100),(610117,'高陵区',610100),(610122,'蓝田县',610100),(610124,'周至县',610100),(610125,'户县',610100),(610200,'铜川市',610000),(610202,'王益区',610200),(610203,'印台区',610200),(610204,'耀州区',610200),(610222,'宜君县',610200),(610300,'宝鸡市',610000),(610302,'渭滨区',610300),(610303,'金台区',610300),(610304,'陈仓区',610300),(610322,'凤翔县',610300),(610323,'岐山县',610300),(610324,'扶风县',610300),(610326,'眉县',610300),(610327,'陇县',610300),(610328,'千阳县',610300),(610329,'麟游县',610300),(610330,'凤县',610300),(610331,'太白县',610300),(610400,'咸阳市',610000),(610402,'秦都区',610400),(610403,'杨陵区',610400),(610404,'渭城区',610400),(610422,'三原县',610400),(610423,'泾阳县',610400),(610424,'乾县',610400),(610425,'礼泉县',610400),(610426,'永寿县',610400),(610427,'彬县',610400),(610428,'长武县',610400),(610429,'旬邑县',610400),(610430,'淳化县',610400),(610431,'武功县',610400),(610481,'兴平市',610400),(610500,'渭南市',610000),(610502,'临渭区',610500),(610503,'华州区',610500),(610522,'潼关县',610500),(610523,'大荔县',610500),(610524,'合阳县',610500),(610525,'澄城县',610500),(610526,'蒲城县',610500),(610527,'白水县',610500),(610528,'富平县',610500),(610581,'韩城市',610500),(610582,'华阴市',610500),(610600,'延安市',610000),(610602,'宝塔区',610600),(610603,'安塞区',610600),(610621,'延长县',610600),(610622,'延川县',610600),(610623,'子长县',610600),(610625,'志丹县',610600),(610626,'吴起县',610600),(610627,'甘泉县',610600),(610628,'富县',610600),(610629,'洛川县',610600),(610630,'宜川县',610600),(610631,'黄龙县',610600),(610632,'黄陵县',610600),(610700,'汉中市',610000),(610702,'汉台区',610700),(610721,'南郑县',610700),(610722,'城固县',610700),(610723,'洋县',610700),(610724,'西乡县',610700),(610725,'勉县',610700),(610726,'宁强县',610700),(610727,'略阳县',610700),(610728,'镇巴县',610700),(610729,'留坝县',610700),(610730,'佛坪县',610700),(610800,'榆林市',610000),(610802,'榆阳区',610800),(610803,'横山区',610800),(610821,'神木县',610800),(610822,'府谷县',610800),(610824,'靖边县',610800),(610825,'定边县',610800),(610826,'绥德县',610800),(610827,'米脂县',610800),(610828,'佳县',610800),(610829,'吴堡县',610800),(610830,'清涧县',610800),(610831,'子洲县',610800),(610900,'安康市',610000),(610902,'汉滨区',610900),(610921,'汉阴县',610900),(610922,'石泉县',610900),(610923,'宁陕县',610900),(610924,'紫阳县',610900),(610925,'岚皋县',610900),(610926,'平利县',610900),(610927,'镇坪县',610900),(610928,'旬阳县',610900),(610929,'白河县',610900),(611000,'商洛市',610000),(611002,'商州区',611000),(611021,'洛南县',611000),(611022,'丹凤县',611000),(611023,'商南县',611000),(611024,'山阳县',611000),(611025,'镇安县',611000),(611026,'柞水县',611000),(620000,'甘肃省',NULL),(620100,'兰州市',620000),(620102,'城关区',620100),(620103,'七里河区',620100),(620104,'西固区',620100),(620105,'安宁区',620100),(620111,'红古区',620100),(620121,'永登县',620100),(620122,'皋兰县',620100),(620123,'榆中县',620100),(620200,'嘉峪关市',620000),(620300,'金昌市',620000),(620302,'金川区',620300),(620321,'永昌县',620300),(620400,'白银市',620000),(620402,'白银区',620400),(620403,'平川区',620400),(620421,'靖远县',620400),(620422,'会宁县',620400),(620423,'景泰县',620400),(620500,'天水市',620000),(620502,'秦州区',620500),(620503,'麦积区',620500),(620521,'清水县',620500),(620522,'秦安县',620500),(620523,'甘谷县',620500),(620524,'武山县',620500),(620525,'张家川回族自治县',620500),(620600,'武威市',620000),(620602,'凉州区',620600),(620621,'民勤县',620600),(620622,'古浪县',620600),(620623,'天祝藏族自治县',620600),(620700,'张掖市',620000),(620702,'甘州区',620700),(620721,'肃南裕固族自治县',620700),(620722,'民乐县',620700),(620723,'临泽县',620700),(620724,'高台县',620700),(620725,'山丹县',620700),(620800,'平凉市',620000),(620802,'崆峒区',620800),(620821,'泾川县',620800),(620822,'灵台县',620800),(620823,'崇信县',620800),(620824,'华亭县',620800),(620825,'庄浪县',620800),(620826,'静宁县',620800),(620900,'酒泉市',620000),(620902,'肃州区',620900),(620921,'金塔县',620900),(620922,'瓜州县',620900),(620923,'肃北蒙古族自治县',620900),(620924,'阿克塞哈萨克族自治县',620900),(620981,'玉门市',620900),(620982,'敦煌市',620900),(621000,'庆阳市',620000),(621002,'西峰区',621000),(621021,'庆城县',621000),(621022,'环县',621000),(621023,'华池县',621000),(621024,'合水县',621000),(621025,'正宁县',621000),(621026,'宁县',621000),(621027,'镇原县',621000),(621100,'定西市',620000),(621102,'安定区',621100),(621121,'通渭县',621100),(621122,'陇西县',621100),(621123,'渭源县',621100),(621124,'临洮县',621100),(621125,'漳县',621100),(621126,'岷县',621100),(621200,'陇南市',620000),(621202,'武都区',621200),(621221,'成县',621200),(621222,'文县',621200),(621223,'宕昌县',621200),(621224,'康县',621200),(621225,'西和县',621200),(621226,'礼县',621200),(621227,'徽县',621200),(621228,'两当县',621200),(622900,'临夏回族自治州',620000),(622901,'临夏市',622900),(622921,'临夏县',622900),(622922,'康乐县',622900),(622923,'永靖县',622900),(622924,'广河县',622900),(622925,'和政县',622900),(622926,'东乡族自治县',622900),(622927,'积石山保安族东乡族撒拉族自治县',622900),(623000,'甘南藏族自治州',620000),(623001,'合作市',623000),(623021,'临潭县',623000),(623022,'卓尼县',623000),(623023,'舟曲县',623000),(623024,'迭部县',623000),(623025,'玛曲县',623000),(623026,'碌曲县',623000),(623027,'夏河县',623000),(630000,'青海省',NULL),(630100,'西宁市',630000),(630102,'城东区',630100),(630103,'城中区',630100),(630104,'城西区',630100),(630105,'城北区',630100),(630121,'大通回族土族自治县',630100),(630122,'湟中县',630100),(630123,'湟源县',630100),(630200,'海东市',630000),(630202,'乐都区',630200),(630203,'平安区',630200),(630222,'民和回族土族自治县',630200),(630223,'互助土族自治县',630200),(630224,'化隆回族自治县',630200),(630225,'循化撒拉族自治县',630200),(632200,'海北藏族自治州',630000),(632221,'门源回族自治县',632200),(632222,'祁连县',632200),(632223,'海晏县',632200),(632224,'刚察县',632200),(632300,'黄南藏族自治州',630000),(632321,'同仁县',632300),(632322,'尖扎县',632300),(632323,'泽库县',632300),(632324,'河南蒙古族自治县',632300),(632500,'海南藏族自治州',630000),(632521,'共和县',632500),(632522,'同德县',632500),(632523,'贵德县',632500),(632524,'兴海县',632500),(632525,'贵南县',632500),(632600,'果洛藏族自治州',630000),(632621,'玛沁县',632600),(632622,'班玛县',632600),(632623,'甘德县',632600),(632624,'达日县',632600),(632625,'久治县',632600),(632626,'玛多县',632600),(632700,'玉树藏族自治州',630000),(632701,'玉树市',632700),(632722,'杂多县',632700),(632723,'称多县',632700),(632724,'治多县',632700),(632725,'囊谦县',632700),(632726,'曲麻莱县',632700),(632800,'海西蒙古族藏族自治州',630000),(632801,'格尔木市',632800),(632802,'德令哈市',632800),(632821,'乌兰县',632800),(632822,'都兰县',632800),(632823,'天峻县',632800),(640000,'宁夏回族自治区',NULL),(640100,'银川市',640000),(640104,'兴庆区',640100),(640105,'西夏区',640100),(640106,'金凤区',640100),(640121,'永宁县',640100),(640122,'贺兰县',640100),(640181,'灵武市',640100),(640200,'石嘴山市',640000),(640202,'大武口区',640200),(640205,'惠农区',640200),(640221,'平罗县',640200),(640300,'吴忠市',640000),(640302,'利通区',640300),(640303,'红寺堡区',640300),(640323,'盐池县',640300),(640324,'同心县',640300),(640381,'青铜峡市',640300),(640400,'固原市',640000),(640402,'原州区',640400),(640422,'西吉县',640400),(640423,'隆德县',640400),(640424,'泾源县',640400),(640425,'彭阳县',640400),(640500,'中卫市',640000),(640502,'沙坡头区',640500),(640521,'中宁县',640500),(640522,'海原县',640500),(650000,'新疆维吾尔自治区',NULL),(650100,'乌鲁木齐市',650000),(650102,'天山区',650100),(650103,'沙依巴克区',650100),(650104,'新市区',650100),(650105,'水磨沟区',650100),(650106,'头屯河区',650100),(650107,'达坂城区',650100),(650109,'米东区',650100),(650121,'乌鲁木齐县',650100),(650200,'克拉玛依市',650000),(650202,'独山子区',650200),(650203,'克拉玛依区',650200),(650204,'白碱滩区',650200),(650205,'乌尔禾区',650200),(650400,'吐鲁番市',650000),(650402,'高昌区',650400),(650421,'鄯善县',650400),(650422,'托克逊县',650400),(650500,'哈密市',650000),(650502,'伊州区',650500),(650521,'巴里坤哈萨克自治县',650500),(650522,'伊吾县',650500),(652300,'昌吉回族自治州',650000),(652301,'昌吉市',652300),(652302,'阜康市',652300),(652323,'呼图壁县',652300),(652324,'玛纳斯县',652300),(652325,'奇台县',652300),(652327,'吉木萨尔县',652300),(652328,'木垒哈萨克自治县',652300),(652700,'博尔塔拉蒙古自治州',650000),(652701,'博乐市',652700),(652702,'阿拉山口市',652700),(652722,'精河县',652700),(652723,'温泉县',652700),(652800,'巴音郭楞蒙古自治州',650000),(652801,'库尔勒市',652800),(652822,'轮台县',652800),(652823,'尉犁县',652800),(652824,'若羌县',652800),(652825,'且末县',652800),(652826,'焉耆回族自治县',652800),(652827,'和静县',652800),(652828,'和硕县',652800),(652829,'博湖县',652800),(652900,'阿克苏地区',650000),(652901,'阿克苏市',652900),(652922,'温宿县',652900),(652923,'库车县',652900),(652924,'沙雅县',652900),(652925,'新和县',652900),(652926,'拜城县',652900),(652927,'乌什县',652900),(652928,'阿瓦提县',652900),(652929,'柯坪县',652900),(653000,'克孜勒苏柯尔克孜自治州',650000),(653001,'阿图什市',653000),(653022,'阿克陶县',653000),(653023,'阿合奇县',653000),(653024,'乌恰县',653000),(653100,'喀什地区',650000),(653101,'喀什市',653100),(653121,'疏附县',653100),(653122,'疏勒县',653100),(653123,'英吉沙县',653100),(653124,'泽普县',653100),(653125,'莎车县',653100),(653126,'叶城县',653100),(653127,'麦盖提县',653100),(653128,'岳普湖县',653100),(653129,'伽师县',653100),(653130,'巴楚县',653100),(653131,'塔什库尔干塔吉克自治县',653100),(653200,'和田地区',650000),(653201,'和田市',653200),(653221,'和田县',653200),(653222,'墨玉县',653200),(653223,'皮山县',653200),(653224,'洛浦县',653200),(653225,'策勒县',653200),(653226,'于田县',653200),(653227,'民丰县',653200),(654000,'伊犁哈萨克自治州',650000),(654002,'伊宁市',654000),(654003,'奎屯市',654000),(654004,'霍尔果斯市',654000),(654021,'伊宁县',654000),(654022,'察布查尔锡伯自治县',654000),(654023,'霍城县',654000),(654024,'巩留县',654000),(654025,'新源县',654000),(654026,'昭苏县',654000),(654027,'特克斯县',654000),(654028,'尼勒克县',654000),(654200,'塔城地区',650000),(654201,'塔城市',654200),(654202,'乌苏市',654200),(654221,'额敏县',654200),(654223,'沙湾县',654200),(654224,'托里县',654200),(654225,'裕民县',654200),(654226,'和布克赛尔蒙古自治县',654200),(654300,'阿勒泰地区',650000),(654301,'阿勒泰市',654300),(654321,'布尔津县',654300),(654322,'富蕴县',654300),(654323,'福海县',654300),(654324,'哈巴河县',654300),(654325,'青河县',654300),(654326,'吉木乃县',654300),(659000,'自治区直辖县级行政区划',650000),(659001,'石河子市',659000),(659002,'阿拉尔市',659000),(659003,'图木舒克市',659000),(659004,'五家渠市',659000),(659006,'铁门关市',659000),(710000,'台湾省',NULL),(810000,'香港特别行政区',NULL),(820000,'澳门特别行政区',NULL);
/*!40000 ALTER TABLE `tb_areas` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_auth_qq`
--

DROP TABLE IF EXISTS `tb_auth_qq`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_auth_qq` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `openid` varchar(64) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_auth_qq_user_id_d821869a_fk_tb_user_id` (`user_id`),
  KEY `tb_auth_qq_openid_dd5aa212` (`openid`),
  CONSTRAINT `tb_auth_qq_user_id_d821869a_fk_tb_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_auth_qq`
--

LOCK TABLES `tb_auth_qq` WRITE;
/*!40000 ALTER TABLE `tb_auth_qq` DISABLE KEYS */;
INSERT INTO `tb_auth_qq` VALUES (1,'2019-02-23 03:46:52.592069','2019-02-23 03:46:52.592205','0D5436AB6A319B303BF2020D250C5023',8);
/*!40000 ALTER TABLE `tb_auth_qq` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_brand`
--

DROP TABLE IF EXISTS `tb_brand`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_brand` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `name` varchar(20) NOT NULL,
  `logo` varchar(100) NOT NULL,
  `first_letter` varchar(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_brand`
--

LOCK TABLES `tb_brand` WRITE;
/*!40000 ALTER TABLE `tb_brand` DISABLE KEYS */;
INSERT INTO `tb_brand` VALUES (1,'2018-04-11 15:58:07.692997','2018-04-11 15:58:07.693099','Apple','group1/M00/00/02/CtM3BVrOMI-AVPWrAAAPN5YrVxw2187795','A'),(2,'2018-04-14 03:01:13.193045','2018-04-14 03:01:13.193091','华为（HUAWEI）','group1/M00/00/02/CtM3BVrRbvmAJ0cWAAAefuA2Xqo3496149','H');
/*!40000 ALTER TABLE `tb_brand` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_content`
--

DROP TABLE IF EXISTS `tb_content`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_content` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `title` varchar(100) NOT NULL,
  `url` varchar(300) NOT NULL,
  `image` varchar(100) DEFAULT NULL,
  `text` longtext,
  `sequence` int(11) NOT NULL,
  `status` tinyint(1) NOT NULL,
  `category_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_content_category_id_c6e5ac73_fk_tb_content_category_id` (`category_id`),
  CONSTRAINT `tb_content_category_id_c6e5ac73_fk_tb_content_category_id` FOREIGN KEY (`category_id`) REFERENCES `tb_content_category` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=124 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_content`
--

LOCK TABLES `tb_content` WRITE;
/*!40000 ALTER TABLE `tb_content` DISABLE KEYS */;
INSERT INTO `tb_content` VALUES (1,'2018-04-09 16:50:23.230734','2018-04-09 16:50:23.230780','美图M8s','http://www.itcast.cn','group1/M00/00/01/CtM3BVrLmc-AJdVSAAEI5Wm7zaw8639396','',1,1,1),(2,'2018-04-09 16:51:46.173309','2018-04-09 16:51:46.173354','黑色星期五','http://www.itcast.cn','group1/M00/00/01/CtM3BVrLmiKANEeLAAFfMRWFbY86177278','',2,1,1),(3,'2018-04-09 16:52:22.471123','2018-04-09 16:52:22.471191','厨卫365','http://www.itcast.cn','group1/M00/00/01/CtM3BVrLmkaAPIMJAAESCG7GAh43642702','',3,1,1),(4,'2018-04-09 16:53:10.539505','2018-04-09 16:53:10.539553','君乐宝买一送一','http://www.itcast.cn','group1/M00/00/01/CtM3BVrLmnaADtSKAAGlxZuk7uk4998927','',4,1,1),(5,'2018-04-09 16:53:57.409847','2018-04-09 16:53:57.409913','i7顽石低至4199元','http://www.itcast.cn','','',1,1,2),(6,'2018-04-09 16:54:36.805870','2018-04-09 16:54:36.805912','奥克斯专场 正1匹空调1313元抢','http://www.itcast.cn','','',2,1,2),(7,'2018-04-09 16:55:37.481628','2018-04-09 16:55:37.481707','荣耀9青春版 高配 领券立减220元','http://www.itcast.cn','','',3,1,2),(8,'2018-04-09 16:55:59.644645','2018-04-09 16:55:59.644697','美多探索公益新模式','http://www.itcast.cn','','',4,1,2),(9,'2018-04-09 16:57:05.390017','2018-04-09 16:57:05.390098','冰箱洗衣机专场 套购9折','http://www.itcast.cn','','',5,1,2),(10,'2018-04-09 16:57:41.680151','2018-04-09 16:57:41.680198','超市美食家 满188减100','http://www.itcast.cn','','',6,1,2),(11,'2018-04-09 16:58:27.074643','2018-04-09 16:58:27.074831','电竟之日 电脑最高减1000元','http://www.itcast.cn','','',7,1,2),(12,'2018-04-09 16:59:36.669624','2018-04-09 16:59:36.669664','好友联盟双双赚','http://www.itcast.cn','group1/M00/00/01/CtM3BVrLm_iAILnwAACbl1lbG3U8255973','',1,1,3),(14,'2018-04-09 17:01:42.028961','2018-04-09 17:01:42.029005','荣耀V10','http://www.itcast.cn','group1/M00/00/01/CtM3BVrLnHaATJWfAABcalxfbWk5995788','',1,1,5),(15,'2018-04-09 17:01:56.504762','2018-04-09 17:01:56.504805','手机','http://www.itcast.cn','','',1,1,6),(16,'2018-04-09 17:02:11.330329','2018-04-09 17:02:11.330373','配件','http://www.itcast.cn','','',2,1,6),(17,'2018-04-09 17:02:27.171626','2018-04-09 17:02:27.171669','充值','http://www.itcast.cn','','',3,1,6),(18,'2018-04-09 17:02:47.086939','2018-04-09 17:02:47.086983','优惠券','http://www.itcast.cn','','',4,1,6),(19,'2018-04-09 17:03:06.144946','2018-04-09 17:03:06.144990','荣耀手机','http://www.itcast.cn','','',1,1,7),(20,'2018-04-09 17:03:23.268285','2018-04-09 17:03:23.268333','国美手机','http://www.itcast.cn','','',2,1,7),(21,'2018-04-09 17:03:36.403398','2018-04-09 17:03:36.403463','华为手机','http://www.itcast.cn','','',3,1,7),(22,'2018-04-09 17:03:54.000395','2018-04-09 17:03:54.000460','热销推荐','http://www.itcast.cn','','',4,1,7),(23,'2018-04-09 17:04:12.517924','2018-04-09 17:04:12.517972','以旧换新','http://www.itcast.cn','','',5,1,7),(24,'2018-04-09 17:04:29.338056','2018-04-09 17:04:29.338132','潮3C','http://www.itcast.cn','','',6,1,7),(25,'2018-04-09 17:04:45.403852','2018-04-09 17:04:45.403917','全面屏','http://www.itcast.cn','','',7,1,7),(26,'2018-04-09 17:04:58.159270','2018-04-09 17:04:58.159321','守护宝','http://www.itcast.cn','','',8,1,7),(27,'2018-04-09 17:05:14.234438','2018-04-09 17:05:14.234482','存储卡','http://www.itcast.cn','','',9,1,7),(28,'2018-04-10 08:51:33.422870','2018-04-10 08:51:33.422915','360手机 N6 Pro 全网通','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMexWAfodJAAAhg8MeEWU8364862','￥ 2699.00',1,1,8),(29,'2018-04-10 08:52:50.280197','2018-04-10 08:52:50.280243','iPhone X','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMe2KAGXDKAAAVASh8SzY6938726','￥ 7788.00',2,1,8),(30,'2018-04-10 08:56:33.016220','2018-04-10 09:16:59.298002','荣耀 畅玩7A 全网通 极光蓝','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMgQuAM4-sAABPvjDmrZE7647305','￥ 749.00',3,1,8),(31,'2018-04-10 08:57:52.744863','2018-04-10 09:18:36.211831','魅蓝 S6 全网通','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMgWyAH_f1AAAQuFJkR2o1196559','￥1199.00',4,1,8),(32,'2018-04-10 08:59:19.379261','2018-04-10 09:20:59.490599','红米5Plus 全网通 浅蓝','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMgX2AeXiGAABuWTn7Wr09762364','￥1299.00',5,1,8),(33,'2018-04-10 09:19:52.078636','2018-04-10 09:21:15.251997','OPPO A1 全网通 深海蓝','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMgbiARBnzAABbhp78Lqs6191821','￥1399.00',6,1,8),(34,'2018-04-10 09:20:43.322594','2018-04-10 09:21:08.660170','华为 nova3e 全网通 幻夜黑','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMgeuAYEocAABd3TzhhGw1571126','￥1999.00',7,1,8),(35,'2018-04-10 09:22:14.074590','2018-04-10 09:22:14.074656','OPPO R15 全网通 梦镜红','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMgkaAWyHAAABbrVH9a7o5762009','￥3299.00',8,1,8),(36,'2018-04-10 09:22:52.988391','2018-04-10 09:22:52.988518','荣耀V10 全网通 标配版 沙滩金','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMgmyAB_1AAABoaAzPPW86045138','￥2499.00',9,1,8),(37,'2018-04-10 09:23:26.963050','2018-04-10 09:23:26.963128','vivo X21 异形全面屏 全网通','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMgo6Aa3OTAAA82h3PXzw9976088','￥3198.00',10,1,8),(38,'2018-04-10 09:29:30.877589','2018-04-10 09:29:30.877630','华为P10 全网通','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMg_qACjBsAAActVXQUoc6433633','￥3488.00',1,1,10),(39,'2018-04-10 09:29:59.145437','2018-04-10 09:29:59.145821','小米 红米5 全网通版','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhBeAaZ9OAABuZHjPsV88472096','￥699.00',2,1,10),(40,'2018-04-10 09:30:29.868913','2018-04-10 09:30:29.868969','魅蓝 Note6 全网通公开版','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhDWAEwgEAABPce7je4w1228836','￥1499.00',3,1,10),(41,'2018-04-10 09:31:07.855868','2018-04-10 09:31:07.855915','红米5Plus 全网通','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhFuAB5eZAAAaQIF-UNs3707070','￥1299.00',4,1,10),(42,'2018-04-10 09:31:42.980397','2018-04-10 09:31:42.980445','荣耀9青春版 标配版','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhH6AAjD4AABS1vBu6x01229529','￥1099.00',5,1,10),(43,'2018-04-10 09:34:08.867671','2018-04-10 09:34:08.867712','华为 畅享8 全网通','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhRCAB5hsAAAQZye4aIM5257140','￥1299.00',6,1,10),(44,'2018-04-10 09:35:12.710916','2018-04-10 09:35:12.710989','荣耀 畅玩7X 尊享版','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhVCAFC8tAABonSNLGHA3584281','￥1799.00',7,1,10),(45,'2018-04-10 09:35:42.251919','2018-04-10 09:35:42.251963','华为 nova3e 全网通 幻夜黑','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhW6Ac7QMAABd3TzhhGw0583536','￥1999.00',8,1,10),(46,'2018-04-10 09:36:12.028644','2018-04-10 09:36:12.028685','魅族 RPO 7 Plus 全网通','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhYyAOjMVAABU1kCuf_48013827','￥2799.00',9,1,10),(47,'2018-04-10 09:36:36.804759','2018-04-10 09:36:36.804804','三星 S8 Plus 全网通','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhaSAK3QLAAA7LKRGwzQ0348867','￥5499.00',10,1,10),(48,'2018-04-10 09:38:59.226650','2018-04-10 09:38:59.226695','Aogress一体双用数据线DC-28金','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhjOAdMNbAAAR1JGA_cA5064317','￥29.00',1,1,11),(49,'2018-04-10 09:39:32.483523','2018-04-10 09:39:32.483585','黑客iPhone X 钢化膜','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhlSAP_27AAAW_YBdNEk8530912','￥29.00',2,1,11),(50,'2018-04-10 09:40:08.968290','2018-04-10 09:40:08.968367','黑客 3D曲面 全屏钢化膜','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhniADXZpAAALTWT-dfQ6160056','￥99.00',4,1,11),(51,'2018-04-10 09:40:40.405191','2018-04-10 09:40:40.405231','三星（SAMSUNG）存储卡 64G','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhpiAV3lJAABiLlkgy2Y9166507','￥169.00',5,1,11),(52,'2018-04-10 09:42:15.130337','2018-04-10 09:42:15.130419','浦诺菲(pivoful) PUC-15 Type-C 数据线','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhveAOh8EAAA1ykQ-kAU6900992','￥19.90',6,1,11),(53,'2018-04-10 09:43:07.486074','2018-04-10 09:43:07.486118','好格(Aogress) A-100E移动电源','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMhyuAEf95AABFDj_owsg4241256','￥99.00',7,1,11),(54,'2018-04-10 09:43:38.901332','2018-04-10 09:43:38.901374','卡士奇 存储卡','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMh0qAavITAABOVXYg3SI5232882','￥29.90',8,1,11),(55,'2018-04-10 09:44:39.359738','2018-04-10 09:44:39.359783','捷波朗(Jabra)OTE23 运动蓝牙耳机','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMh4eAWdF2AAA-Fkkc5rM1921911','￥299.00',9,1,11),(56,'2018-04-10 09:45:17.804328','2018-04-10 09:45:17.804368','besiterBST-0109FO强尼思','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMh62AUlDTAAA-SfqPszY5890026','￥99.00',10,1,11),(57,'2018-04-10 09:58:35.242596','2018-04-10 09:58:35.242654','小米九号平衡车','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMisuAJnyWAABYJxXfN8w9822011','加100元送小米汽车',1,1,16),(58,'2018-04-10 09:59:16.706582','2018-04-10 09:59:16.706628','小米空气净化器2','http://www.itcast.cn','group1/M00/00/01/CtM3BVrMivSAUTWcAAANpJ-t9xg5938130','加价10元送滤芯',2,1,16),(59,'2018-04-11 06:39:11.953183','2018-04-11 06:39:11.953229','Apple Watch S3 GPS版','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNrY-AdBacAAA7DYB8sjU0120233','加1元换够蓝牙耳机',3,1,16),(60,'2018-04-11 06:40:29.270078','2018-04-11 06:40:29.270123','裴讯智能体脂秤S7P','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNrd2AbRH-AAALOATUqqM8030242','加1元换够南浮电池',4,1,16),(61,'2018-04-11 06:41:03.054344','2018-04-11 06:41:03.054390','360儿童手表电话SE2','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNrf-AJ1ZjAAB_vAApFkw8201014','￥169.00',5,1,16),(62,'2018-04-11 06:42:11.402524','2018-04-11 06:42:11.402782','S2PGHW-521蓝牙耳机','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNrkOAYXcbAABQocGJtes4517631','￥449.00',6,1,16),(63,'2018-04-11 06:42:47.985726','2018-04-11 06:42:47.985771','科大讯飞 翻译机','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNrmeAPQkiAAAKCg08y3w4028142','加1元换够电池',7,1,16),(64,'2018-04-11 06:43:19.285413','2018-04-11 06:43:19.285477','Apple AirPods蓝牙耳机','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNroeAUxHkAAAKhSBwnSk3723835','￥1288.00',8,1,16),(65,'2018-04-11 06:43:59.651504','2018-04-11 06:43:59.651581','ILIFE V5 智能扫地机器人','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNrq-AbFajAABb8Hp05302964728','加1元换够充电器',9,1,16),(66,'2018-04-11 06:44:29.649982','2018-04-11 06:44:29.650036','360记录仪M301','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNrs2AMHPbAABMxVYJeMo0602527','￥319.00',10,1,16),(67,'2018-04-11 06:46:32.465443','2018-04-11 06:46:32.465515','Apple iPad 平板电脑 2018款','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNr0iAAbCEAABZEWPGxc48830214','￥2388.00',1,1,18),(68,'2018-04-11 06:47:11.689035','2018-04-11 06:47:11.689102','华硕飞行堡垒五代游戏本','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNr2-AbNUxAABwpN-gR8E7784256','￥5999.00',2,1,18),(69,'2018-04-11 06:48:08.629095','2018-04-11 06:48:08.629138','ThinkPad T480','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNr6iAWKHsAAAcWfJ6OD00441704','￥8399.00',3,1,18),(70,'2018-04-11 06:48:34.571822','2018-04-11 06:48:34.571868','华硕飞行堡垒五代游戏本','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNr8KAD6b2AAByGLpNQV01684706','￥6299.00',4,1,18),(71,'2018-04-11 06:49:16.497815','2018-04-26 12:46:17.580482','艾比格特 无线移动WIFI','http://www.itcast.cn','group1/M00/00/02/CtM3BVrhyhmAehqbAAA3XtuXCto1322736','￥1399.00',5,1,18),(72,'2018-04-11 06:49:49.839309','2018-04-11 06:49:49.839349','360 巴迪龙儿童手表','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNsA2AQUMbAAAbb_vBV6I1599925','￥999.00',6,1,18),(73,'2018-04-11 06:50:19.092920','2018-04-11 06:50:19.093006','Lenovo 星球大战 绝地挑战 AR眼镜','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNsCuAUvllAAAOkY17G984349519','￥1999.00',7,1,18),(74,'2018-04-11 06:50:41.252312','2018-04-11 06:50:41.252453','HTC VR眼镜','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNsEGAZTfyAAAasplERbc8856337','￥4299.00',8,1,18),(75,'2018-04-11 06:51:12.922333','2018-04-11 06:51:12.922378','Apple Watch S3 蜂窝版','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNsGCAeDZeAABtIYY5-s41601603','￥3188.00',9,1,18),(76,'2018-04-11 06:51:40.271373','2018-04-11 06:51:40.271422','360电话手表 X1Pro','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNsHyANXdyAABeDo_Qzeg1095047','￥1499.00',10,1,18),(77,'2018-04-11 06:53:31.774835','2018-04-11 06:53:31.774982','小米笔记本Air','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNsOuAQbJYAABoachTxTo8223966','',1,1,13),(78,'2018-04-11 06:53:46.540973','2018-04-11 06:53:46.541041','电脑','http://www.itcast.cn','','',1,1,14),(79,'2018-04-11 06:54:00.356620','2018-04-11 06:54:00.356669','数码','http://www.itcast.cn','','',2,1,14),(80,'2018-04-11 06:54:11.361324','2018-04-11 06:54:11.361367','配件','http://www.itcast.cn','','',3,1,14),(81,'2018-04-11 06:54:21.777505','2018-04-11 06:54:21.777549','潮电子','http://www.itcast.cn','','',4,1,14),(82,'2018-04-11 06:54:36.170021','2018-04-11 06:54:36.170082','iPad新品','http://www.itcast.cn','','',1,1,15),(83,'2018-04-11 06:54:50.484452','2018-04-11 06:54:50.484499','限量购','http://www.itcast.cn','','',2,1,15),(84,'2018-04-11 06:55:11.333884','2018-04-11 06:55:11.333934','单反相机','http://www.itcast.cn','','',3,1,15),(85,'2018-04-11 06:55:31.975211','2018-04-11 06:55:31.975285','智能家具','http://www.itcast.cn','','',4,1,15),(86,'2018-04-11 06:55:43.070748','2018-04-11 06:55:43.070796','智能路由','http://www.itcast.cn','','',5,1,15),(87,'2018-04-11 06:55:57.563944','2018-04-11 06:55:57.563999','限时抢','http://www.itcast.cn','','',6,1,15),(88,'2018-04-11 06:56:14.604570','2018-04-11 06:56:14.604661','颂拓','http://www.itcast.cn','','',7,1,15),(89,'2018-04-11 06:56:25.639226','2018-04-11 06:56:25.639271','微单','http://www.itcast.cn','','',8,1,15),(90,'2018-04-11 06:56:34.836303','2018-04-11 06:56:34.836374','耳机','http://www.itcast.cn','','',9,1,15),(91,'2018-04-11 06:56:58.113652','2018-04-11 06:56:58.113703','水星家纺','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNsbqAbi4CAABYmW4pmPA1782942','',1,1,21),(92,'2018-04-11 06:57:13.215501','2018-04-11 06:57:13.215548','家具日用','http://www.itcast.cn','','',1,1,22),(93,'2018-04-11 06:57:30.689560','2018-04-11 06:57:30.689647','家纺寝具','http://www.itcast.cn','','',2,1,22),(94,'2018-04-11 06:57:50.983438','2018-04-11 06:57:50.983481','住宅家具','http://www.itcast.cn','','',3,1,22),(95,'2018-04-11 06:58:03.324082','2018-04-11 06:58:03.324128','厨具餐饮','http://www.itcast.cn','','',1,1,23),(96,'2018-04-11 06:58:13.694750','2018-04-11 06:58:13.694795','被子','http://www.itcast.cn','','',2,1,23),(97,'2018-04-11 06:58:31.412903','2018-04-11 06:58:31.412949','实木床','http://www.itcast.cn','','',3,1,23),(98,'2018-04-11 06:58:52.598947','2018-04-11 06:58:52.598992','箭牌马桶','http://www.itcast.cn','','',4,1,23),(99,'2018-04-11 06:59:07.562439','2018-04-11 06:59:07.562541','指纹锁','http://www.itcast.cn','','',5,1,23),(100,'2018-04-11 06:59:24.628095','2018-04-11 06:59:24.628162','电饭煲','http://www.itcast.cn','','',6,1,23),(101,'2018-04-11 06:59:37.707050','2018-04-11 06:59:37.707098','热水器','http://www.itcast.cn','','',7,1,23),(102,'2018-04-11 06:59:48.635658','2018-04-11 06:59:48.635707','席梦思','http://www.itcast.cn','','',8,1,23),(103,'2018-04-11 06:59:57.465653','2018-04-11 06:59:57.465696','沙发','http://www.itcast.cn','','',9,1,23),(104,'2018-04-11 07:02:03.780376','2018-04-11 07:02:03.780419','洁柔纸巾','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNsuuAQo25AAAmP_AGNMA9808303','￥45.90',1,1,24),(105,'2018-04-11 07:02:46.547111','2018-04-11 07:02:46.547187','花仙子除湿剂','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNsxaAeU4HAAAkQDJCGSY6809195','￥19.90',2,1,24),(106,'2018-04-11 07:03:18.325791','2018-04-11 07:03:18.325869','超能洗衣液','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNszaAMu2PAACwnbap8zI9797082','惊喜价',3,1,24),(107,'2018-04-11 07:04:04.509724','2018-04-11 07:04:04.509770','创简坊 扫帚','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNs2SAf2DEAAAGl2-3v5k2172012','惊喜价',4,1,24),(108,'2018-04-11 07:04:34.799452','2018-04-11 07:04:34.799494','万象玻璃杯','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNs4KAIlJKAAAQmKypd2c1901811','爆款热销',5,1,24),(109,'2018-04-11 07:05:10.845016','2018-04-11 07:05:10.845072','爱丽丝收纳箱','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNs6aAea7bAAAIoddXpoA5854653','￥66.00',6,1,24),(110,'2018-04-11 07:05:41.147138','2018-04-11 07:05:41.147210','塑料袋 加厚','http://www.itcast.cn','group1/M00/00/01/CtM3BVrNs8WAZsplAAB-c4wo3kI9077289','跳楼价',7,1,24),(111,'2018-04-11 07:06:12.674584','2018-04-11 07:06:12.674634','特白惠 塑料杯','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNs-SAaLqBAAAPB44z-fw7327519','实惠价',8,1,24),(112,'2018-04-11 07:06:54.675238','2018-04-11 07:06:54.675282','Bormioli Rocco意大利进口水果杯','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNtA6AFtbDAAAVJIjSdl43078544','买一送一',9,1,24),(113,'2018-04-11 07:07:29.946108','2018-04-11 07:07:29.946151','宜兴紫砂壶','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNtDGAdlzlAAAZZRjOIrQ5323041','￥220.00',10,1,24),(114,'2018-04-11 07:09:57.168028','2018-04-11 07:09:57.168075','苏泊尔 炒锅','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNtMWANuqTAACac0TCaxU2674435','￥329.00 惠',1,1,25),(115,'2018-04-11 07:10:32.939492','2018-04-11 07:10:32.939538','双立人 多用双刀','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNtOiAKex1AAAOZc14LLQ2319263','惊喜价',2,1,25),(116,'2018-04-11 07:11:13.792342','2018-04-11 07:11:13.792386','爱仕达高压锅','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNtRGAGUbMAACY-WS_oQg9101415','特惠价',3,1,25),(117,'2018-04-11 07:12:01.447582','2018-04-11 07:12:01.447628','维艾圆形不秀钢盆','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNtUGACPW-AAAWNwYc_Yg9317761','￥69.90',4,1,25),(118,'2018-04-11 07:12:34.001525','2018-04-11 07:12:34.001609','家栢利304不锈钢壁挂','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNtWKAUKPkAADhQEAcAgQ4155172','￥198.00',5,1,25),(119,'2018-04-11 07:13:17.630873','2018-04-11 07:13:17.630916','生物海瓷','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNtY2ABEOfAAAWaWuGKss3304555','震撼价',6,1,25),(120,'2018-04-11 07:13:45.655300','2018-04-11 07:13:45.655340','实木筷','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNtamAdrqPAAAYsg3AvQ86108884','买二送一',7,1,25),(121,'2018-04-11 07:14:11.876255','2018-04-11 07:14:11.876328','菜板','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNtcOAYTH1AABVIz70wKU1556174','只要￥149.00',8,1,25),(122,'2018-04-11 07:14:42.828364','2018-04-11 07:14:42.828410','刻度玻璃瓶','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNteKAZhHCAAAMrIL-ugE2533088','白菜价',9,1,25),(123,'2018-04-11 07:15:11.019433','2018-04-11 07:15:11.019475','韩国进口 密封盒','http://www.itcast.cn','group1/M00/00/02/CtM3BVrNtf-AY0FGAAAZwGscZq42512400','￥39.00',10,1,25);
/*!40000 ALTER TABLE `tb_content` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_content_category`
--

DROP TABLE IF EXISTS `tb_content_category`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_content_category` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `name` varchar(50) NOT NULL,
  `key` varchar(50) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_content_category`
--

LOCK TABLES `tb_content_category` WRITE;
/*!40000 ALTER TABLE `tb_content_category` DISABLE KEYS */;
INSERT INTO `tb_content_category` VALUES (1,'2018-04-09 16:04:47.411368','2018-04-09 16:15:26.439825','轮播图','index_lbt'),(2,'2018-04-09 16:06:12.495372','2018-04-09 16:15:32.385060','快讯','index_kx'),(3,'2018-04-09 16:08:36.725277','2018-04-09 16:15:39.930440','页头广告','index_ytgg'),(5,'2018-04-09 16:16:47.531007','2018-04-09 16:16:47.531082','1楼Logo','index_1f_logo'),(6,'2018-04-09 16:17:49.114299','2018-04-09 16:17:49.114342','1楼频道','index_1f_pd'),(7,'2018-04-09 16:18:04.659549','2018-04-09 16:18:04.659588','1楼标签','index_1f_bq'),(8,'2018-04-09 16:18:36.176926','2018-04-09 16:18:36.176991','1楼时尚新品','index_1f_ssxp'),(10,'2018-04-09 16:19:24.489532','2018-04-10 09:49:38.621008','1楼畅享低价','index_1f_cxdj'),(11,'2018-04-09 16:19:46.992482','2018-04-09 16:19:46.992525','1楼手机配件','index_1f_sjpj'),(13,'2018-04-09 16:20:32.331884','2018-04-09 16:20:32.331927','2楼Logo','index_2f_logo'),(14,'2018-04-09 16:20:46.334441','2018-04-09 16:20:46.334481','2楼频道','index_2f_pd'),(15,'2018-04-09 16:21:04.265294','2018-04-09 16:21:04.265336','2楼标签','index_2f_bq'),(16,'2018-04-09 16:21:22.869586','2018-04-10 09:51:49.310917','2楼加价换够','index_2f_jjhg'),(18,'2018-04-09 16:21:59.579570','2018-04-10 09:49:44.891002','2楼畅享低价','index_2f_cxdj'),(21,'2018-04-09 16:22:43.365608','2018-04-09 16:22:43.365653','3楼Logo','index_3f_logo'),(22,'2018-04-09 16:22:55.358798','2018-04-09 16:22:55.358856','3楼频道','index_3f_pd'),(23,'2018-04-09 16:23:05.211747','2018-04-09 16:23:05.211785','3楼标签','index_3f_bq'),(24,'2018-04-09 16:24:01.858753','2018-04-09 16:24:01.858803','3楼生活用品','index_3f_shyp'),(25,'2018-04-09 16:24:17.621898','2018-04-09 16:24:17.621942','3楼厨房用品','index_3f_cfyp');
/*!40000 ALTER TABLE `tb_content_category` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_goods`
--

DROP TABLE IF EXISTS `tb_goods`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_goods` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `name` varchar(50) NOT NULL,
  `sales` int(11) NOT NULL,
  `comments` int(11) NOT NULL,
  `brand_id` int(11) NOT NULL,
  `category1_id` int(11) NOT NULL,
  `category2_id` int(11) NOT NULL,
  `category3_id` int(11) NOT NULL,
  `desc_detail` longtext NOT NULL,
  `desc_pack` longtext NOT NULL,
  `desc_service` longtext NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_goods_brand_id_5c5be571_fk_tb_brand_id` (`brand_id`),
  KEY `tb_goods_category1_id_49c4fab9_fk_tb_goods_category_id` (`category1_id`),
  KEY `tb_goods_category2_id_ea351ced_fk_tb_goods_category_id` (`category2_id`),
  KEY `tb_goods_category3_id_d3ea8415_fk_tb_goods_category_id` (`category3_id`),
  CONSTRAINT `tb_goods_brand_id_5c5be571_fk_tb_brand_id` FOREIGN KEY (`brand_id`) REFERENCES `tb_brand` (`id`),
  CONSTRAINT `tb_goods_category1_id_49c4fab9_fk_tb_goods_category_id` FOREIGN KEY (`category1_id`) REFERENCES `tb_goods_category` (`id`),
  CONSTRAINT `tb_goods_category2_id_ea351ced_fk_tb_goods_category_id` FOREIGN KEY (`category2_id`) REFERENCES `tb_goods_category` (`id`),
  CONSTRAINT `tb_goods_category3_id_d3ea8415_fk_tb_goods_category_id` FOREIGN KEY (`category3_id`) REFERENCES `tb_goods_category` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_goods`
--

LOCK TABLES `tb_goods` WRITE;
/*!40000 ALTER TABLE `tb_goods` DISABLE KEYS */;
INSERT INTO `tb_goods` VALUES (1,'2018-04-11 16:01:28.547507','2019-02-23 11:54:44.401002','Apple MacBook Pro 笔记本',16,4,1,4,45,157,'<h1 style=\"text-align:center\">MacBook Pro 您最得力的助手</h1>\r\n\r\n<p>它纤薄如刃，轻盈如羽，却又比以往速度更快、性能更强大。它为你展现的，是迄今最明亮、最多彩的 Mac 笔记本显示屏。它更配备了触控栏，一个内置于键盘的玻璃面多点触控条，让你能在需要时快速取用各种工具。MacBook Pro 是对我们突破性理念的一场出色演绎，而它，也正期待着演绎你的奇思妙想。</p>\r\n\r\n<p><img alt=\"\" src=\"http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrOQMiAGvPHAADtqTciKRc8279519\" style=\"height:360px; width:750px\" /></p>\r\n\r\n<p><img alt=\"\" src=\"http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrOQXSAbLx2AAJCgscYhy88216086\" style=\"height:1858px; width:750px\" /></p>\r\n\r\n<p><img alt=\"\" src=\"http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrOQcCAap-CAALlB0nCsAk3157451\" style=\"height:2271px; width:750px\" /></p>\r\n\r\n<p><img alt=\"\" src=\"http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrOQhiAVgwfAALNvpwId4s8236297\" style=\"height:1776px; width:750px\" /></p>\r\n\r\n<p><img alt=\"\" src=\"http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrOQimACGAXAAJKAmr2-qQ2403102\" style=\"height:1667px; width:750px\" /></p>\r\n\r\n<p><img alt=\"\" src=\"http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrOQjeAYApsAAJDtceKEm87833689\" style=\"height:1416px; width:750px\" /></p>\r\n\r\n<p>&nbsp;</p>','<h2>包装清单</h2>\r\n\r\n<p>MacBook Air 电源适配器 交流电源插头 电源线</p>','<p>&nbsp;<strong>厂家服务</strong></p>\r\n\r\n<p>1、Mac 电脑整机及所含附件自原始购买之日起享有 1 年保修期。主要部件享有自购买之日起 2 年保修期。Mac 台式电脑所有主要部件包括：主板 (MLB)、处理器 (CPU)、内存、硬盘 (HDD/SSD)、电源和显卡。Mac 笔记本电脑所有主要部件范围包括主板 (MLB)、处理器 (CPU)、内存、硬盘 (HDD/SSD)、电源适配器、键盘和显示屏 (LCD)。可另外购买 AppleCare Protection Plan 全方位服务计划。2、Mac电脑不支持7天无理由退换货，请您再三确认需求后再下单购买。如因质量问题或故障，凭厂商维修中心或特约维修点的质量检测证明，享受7日内退货，15日内换货，15日以上在质保期内享受免费保修等三包服务。3、Apple官方售后服务电话：4006668800，您可以查询本品牌在各地售后服务中心的联系方式及地址。<br />\r\n如因质量问题或故障，凭厂商维修中心或特约维修点的质量检测证明，享受7日内退货，15日内换货，15日以上在质保期内享受免费保修等三包服务！<br />\r\n(注:如厂家在商品介绍中有售后保障的说明,则此商品按照厂家说明执行售后保障服务。) 您可以查询本品牌在各地售后服务中心的联系方式，<a href=\"http://www.apple.com.cn/\" target=\"_blank\">请点击这儿查询......</a><br />\r\n<br />\r\n品牌官方网站：<a href=\"http://www.apple.com.cn/\" target=\"_blank\">http://www.apple.com.cn/</a><br />\r\n售后服务电话：4006668800</p>\r\n\r\n<p><strong>正品行货</strong></p>\r\n\r\n<p>京东商城向您保证所售商品均为正品行货，京东自营商品开具机打发票或电子发票。</p>\r\n\r\n<p><strong>全国联保</strong></p>\r\n\r\n<p>凭质保证书及京东商城发票，可享受全国联保服务（奢侈品、钟表除外；奢侈品、钟表由京东联系保修，享受法定三包售后服务），与您亲临商场选购的商品享受相同的质量保证。京东商城还为您提供具有竞争力的商品价格和<a href=\"https://help.jd.com/help/question-892.html\" target=\"_blank\">运费政策</a>，请您放心购买！&nbsp;<br />\r\n<br />\r\n注：因厂家会在没有任何提前通知的情况下更改产品包装、产地或者一些附件，本司不能确保客户收到的货物与商城图片、产地、附件说明完全一致。只能确保为原厂正货！并且保证与当时市场上同样主流新品一致。若本商城没有及时更新，请大家谅解！</p>'),(2,'2018-04-14 02:09:40.437769','2018-04-25 11:51:50.866215','Apple iPhone 8 Plus',3,1,1,1,38,115,'<p><img alt=\"\" src=\"http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRYoGAC2KAAADDtplWV_04901262\" style=\"height:341px; width:750px\" /></p>\r\n\r\n<p><img alt=\"\" src=\"http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRYpCAS9FFAADxmVbf5qw4487023\" style=\"height:277px; width:750px\" /></p>\r\n\r\n<p><img alt=\"\" src=\"http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRYp6ACUuEAAWXt1XYzNg5251947\" style=\"height:2337px; width:750px\" /></p>\r\n\r\n<p><img alt=\"\" src=\"http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRYqmANdXMAAXn26rWyDY0861997\" style=\"height:2963px; width:750px\" /></p>','<h3>包装清单</h3>\r\n\r\n<p>采用 Lightning 接头的 EarPods *1，iPhone *1，Lightning 至 USB 连接线*1，5W USB 电源适配器*1，Lightning 至3.5毫米耳机插孔转换器*1</p>','<p>&nbsp;<strong>厂家服务</strong></p>\r\n\r\n<p>本产品全国联保，享受三包服务，质保期为：一年质保<br />\r\n如因质量问题或故障，凭厂商维修中心或特约维修点的质量检测证明，享受7日内退货，15日内换货，15日以上在质保期内享受免费保修等三包服务！<br />\r\n(注:如厂家在商品介绍中有售后保障的说明,则此商品按照厂家说明执行售后保障服务。) 您可以查询本品牌在各地售后服务中心的联系方式，<a href=\"http://www.apple.com/cn/\" target=\"_blank\">请点击这儿查询......</a><br />\r\n<br />\r\n品牌官方网站：<a href=\"http://www.apple.com/cn/\" target=\"_blank\">http://www.apple.com/cn/</a><br />\r\n售后服务电话：400-666-8800</p>\r\n\r\n<p>&nbsp;美多<strong>承诺</strong></p>\r\n\r\n<p>美多平台卖家销售并发货的商品，由平台卖家提供发票和相应的售后服务。请您放心购买！<br />\r\n注：因厂家会在没有任何提前通知的情况下更改产品包装、产地或者一些附件，本司不能确保客户收到的货物与商城图片、产地、附件说明完全一致。只能确保为原厂正货！并且保证与当时市场上同样主流新品一致。若本商城没有及时更新，请大家谅解！</p>\r\n\r\n<p><strong>正品行货</strong></p>\r\n\r\n<p>京东商城向您保证所售商品均为正品行货，京东自营商品开具机打发票或电子发票。</p>\r\n\r\n<p><strong>全国联保</strong></p>\r\n\r\n<p>凭质保证书及京东商城发票，可享受全国联保服务（奢侈品、钟表除外；奢侈品、钟表由京东联系保修，享受法定三包售后服务），与您亲临商场选购的商品享受相同的质量保证。京东商城还为您提供具有竞争力的商品价格和<a href=\"https://help.jd.com/help/question-892.html\" target=\"_blank\">运费政策</a>，请您放心购买！&nbsp;<br />\r\n<br />\r\n注：因厂家会在没有任何提前通知的情况下更改产品包装、产地或者一些附件，本司不能确保客户收到的货物与商城图片、产地、附件说明完全一致。只能确保为原厂正货！并且保证与当时市场上同样主流新品一致。若本商城没有及时更新，请大家谅解！</p>'),(3,'2018-04-14 03:03:53.059061','2019-02-24 12:33:43.039514','华为 HUAWEI P10 Plus',16,13,2,1,38,115,'<p><img alt=\"\" src=\"http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRb2yAJ0cWADV9oDHhgG06294506\" style=\"height:10460px; width:750px\" /></p>','<h3>包装清单</h3>\r\n\r\n<p>手机（含内置电池） x 1、大电流华为SuperCharge充电器 x 1、 USB数据线 x 1、半入耳式线控耳机 x 1、快速指南 x 1、三包凭证 x 1、取卡针 x 1、保护壳 x 1</p>','<p>&nbsp;<strong>厂家服务</strong></p>\r\n\r\n<p>本产品全国联保，享受三包服务，质保期为：一年质保<br />\r\n如因质量问题或故障，凭厂商维修中心或特约维修点的质量检测证明，享受7日内退货，15日内换货，15日以上在质保期内享受免费保修等三包服务！<br />\r\n(注:如厂家在商品介绍中有售后保障的说明,则此商品按照厂家说明执行售后保障服务。) 您可以查询本品牌在各地售后服务中心的联系方式，<a href=\"http://www.huawei.com/cn/\" target=\"_blank\">请点击这儿查询......</a><br />\r\n<br />\r\n品牌官方网站：<a href=\"http://www.huawei.com/cn/\" target=\"_blank\">http://www.huawei.com/cn/</a><br />\r\n售后服务电话：400-830-8300</p>\r\n\r\n<p>&nbsp;<strong>京东承诺</strong></p>\r\n\r\n<p>京东平台卖家销售并发货的商品，由平台卖家提供发票和相应的售后服务。请您放心购买！<br />\r\n注：因厂家会在没有任何提前通知的情况下更改产品包装、产地或者一些附件，本司不能确保客户收到的货物与商城图片、产地、附件说明完全一致。只能确保为原厂正货！并且保证与当时市场上同样主流新品一致。若本商城没有及时更新，请大家谅解！</p>\r\n\r\n<p><strong>正品行货</strong></p>\r\n\r\n<p>京东商城向您保证所售商品均为正品行货，京东自营商品开具机打发票或电子发票。</p>\r\n\r\n<p><strong>全国联保</strong></p>\r\n\r\n<p>凭质保证书及京东商城发票，可享受全国联保服务（奢侈品、钟表除外；奢侈品、钟表由京东联系保修，享受法定三包售后服务），与您亲临商场选购的商品享受相同的质量保证。京东商城还为您提供具有竞争力的商品价格和<a href=\"https://help.jd.com/help/question-892.html\" target=\"_blank\">运费政策</a>，请您放心购买！&nbsp;<br />\r\n<br />\r\n注：因厂家会在没有任何提前通知的情况下更改产品包装、产地或者一些附件，本司不能确保客户收到的货物与商城图片、产地、附件说明完全一致。只能确保为原厂正货！并且保证与当时市场上同样主流新品一致。若本商城没有及时更新，请大家谅解</p>');
/*!40000 ALTER TABLE `tb_goods` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_goods_category`
--

DROP TABLE IF EXISTS `tb_goods_category`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_goods_category` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `name` varchar(10) NOT NULL,
  `parent_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_goods_category_parent_id_5abc16fa_fk_tb_goods_category_id` (`parent_id`),
  CONSTRAINT `tb_goods_category_parent_id_5abc16fa_fk_tb_goods_category_id` FOREIGN KEY (`parent_id`) REFERENCES `tb_goods_category` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=556 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_goods_category`
--

LOCK TABLES `tb_goods_category` WRITE;
/*!40000 ALTER TABLE `tb_goods_category` DISABLE KEYS */;
INSERT INTO `tb_goods_category` VALUES (1,'2018-04-09 08:03:18.507741','2018-04-09 08:03:18.507787','手机',NULL),(2,'2018-04-09 08:04:06.884304','2018-04-09 08:04:06.884389','相机',NULL),(3,'2018-04-09 08:04:10.066446','2018-04-09 08:04:10.066496','数码',NULL),(4,'2018-04-09 08:05:08.975211','2018-04-09 08:05:08.975276','电脑',NULL),(5,'2018-04-09 08:05:11.678905','2018-04-09 08:05:11.678946','办公',NULL),(6,'2018-04-09 08:05:15.661520','2018-04-09 08:05:15.661563','家用电器',NULL),(7,'2018-04-09 08:05:31.640302','2018-04-09 08:05:31.640350','家居',NULL),(8,'2018-04-09 08:05:36.662490','2018-04-09 08:05:36.662589','家具',NULL),(9,'2018-04-09 08:05:48.522108','2018-04-09 08:05:48.522167','家装',NULL),(10,'2018-04-09 08:05:51.761687','2018-04-09 08:05:51.761729','厨具',NULL),(11,'2018-04-09 08:06:00.668337','2018-04-09 08:06:00.668376','男装',NULL),(12,'2018-04-09 08:06:03.390254','2018-04-09 08:06:03.390309','女装',NULL),(13,'2018-04-09 08:06:06.366323','2018-04-09 08:06:06.366365','童装',NULL),(14,'2018-04-09 08:06:11.022792','2018-04-09 08:06:11.022872','内衣',NULL),(15,'2018-04-09 08:06:39.183635','2018-04-09 08:06:39.183676','女鞋',NULL),(16,'2018-04-09 08:08:55.929149','2018-04-09 08:08:55.929221','箱包',NULL),(17,'2018-04-09 08:09:02.512577','2018-04-09 08:09:02.512622','钟表',NULL),(18,'2018-04-09 08:09:32.381612','2018-04-09 08:09:32.381652','珠宝',NULL),(19,'2018-04-09 08:09:46.196811','2018-04-09 08:09:46.196853','男鞋',NULL),(20,'2018-04-09 08:09:50.331597','2018-04-09 08:09:50.331661','运动',NULL),(21,'2018-04-09 08:09:53.161070','2018-04-09 08:09:53.161115','户外',NULL),(22,'2018-04-09 08:11:25.870180','2018-04-09 08:11:25.870221','房产',NULL),(23,'2018-04-09 08:11:32.357967','2018-04-09 08:11:32.358008','汽车',NULL),(24,'2018-04-09 08:11:38.193287','2018-04-09 08:11:38.193342','汽车用品',NULL),(25,'2018-04-09 08:11:43.723485','2018-04-09 08:11:43.723526','母婴',NULL),(26,'2018-04-09 08:11:53.163455','2018-04-09 08:11:53.163509','玩具乐器',NULL),(27,'2018-04-09 08:56:04.627338','2018-04-09 08:56:04.627400','食品',NULL),(28,'2018-04-09 08:56:09.781208','2018-04-09 08:56:09.781251','酒类',NULL),(29,'2018-04-09 08:56:13.794667','2018-04-09 08:56:13.794706','生鲜',NULL),(30,'2018-04-09 08:56:16.944058','2018-04-09 08:56:16.944197','特产',NULL),(31,'2018-04-09 08:56:20.053145','2018-04-09 08:56:20.053183','图书',NULL),(32,'2018-04-09 08:56:33.399045','2018-04-09 08:56:33.399100','音像',NULL),(33,'2018-04-09 08:56:40.072007','2018-04-09 08:56:40.072045','电子书',NULL),(34,'2018-04-09 08:56:44.456894','2018-04-09 08:56:44.456936','机票',NULL),(35,'2018-04-09 08:56:50.652838','2018-04-09 08:56:50.652918','酒店',NULL),(36,'2018-04-09 08:56:59.213818','2018-04-09 08:56:59.213867','旅游',NULL),(37,'2018-04-09 08:57:04.589202','2018-04-09 08:57:04.589251','生活',NULL),(38,'2018-04-09 09:29:22.371056','2018-04-09 09:29:22.371100','手机通讯',1),(39,'2018-04-09 09:30:48.196806','2018-04-09 09:30:48.196857','手机配件',1),(40,'2018-04-09 09:34:17.533219','2018-04-09 09:34:17.533261','摄影摄像',2),(41,'2018-04-09 09:34:34.235105','2018-04-09 09:34:34.235143','数码配件',3),(42,'2018-04-09 09:35:34.785967','2018-04-09 09:35:34.786010','影音娱乐',3),(43,'2018-04-09 09:35:45.307642','2018-04-09 09:35:45.307682','智能设备',3),(44,'2018-04-09 09:35:52.032395','2018-04-09 09:35:52.032460','电子教育',3),(45,'2018-04-09 09:37:07.280693','2018-04-09 09:37:07.280744','电脑整机',4),(46,'2018-04-09 09:37:18.429870','2018-04-09 09:37:18.429912','电脑配件',4),(47,'2018-04-09 09:37:28.654365','2018-04-09 09:37:28.654407','外设产品',4),(48,'2018-04-09 09:37:40.238157','2018-04-09 09:37:40.238206','办公设备',5),(49,'2018-04-09 09:37:49.104183','2018-04-09 09:37:49.104222','文具耗材',5),(51,'2018-04-09 09:38:02.637781','2018-04-09 09:38:02.637834','空调',6),(52,'2018-04-09 09:38:07.771986','2018-04-09 09:38:07.772027','洗衣机',6),(53,'2018-04-09 09:38:12.913525','2018-04-09 09:38:12.913568','冰箱',6),(55,'2018-04-09 09:38:38.885029','2018-04-09 09:38:38.885076','生活电器',6),(56,'2018-04-09 09:40:41.787484','2018-04-09 09:40:41.787552','生活日用',7),(57,'2018-04-09 09:41:13.610650','2018-04-09 09:41:13.610693','家纺',7),(58,'2018-04-09 09:41:29.602616','2018-04-09 09:41:29.602671','灯具',8),(59,'2018-04-09 09:41:36.701091','2018-04-09 09:41:36.701133','家具',8),(60,'2018-04-09 09:42:05.085107','2018-04-09 09:42:05.085176','家装软饰',9),(61,'2018-04-09 09:42:14.306983','2018-04-09 09:42:14.307046','家装主材',9),(62,'2018-04-09 09:42:27.065822','2018-04-09 09:42:27.065865','五金电工',9),(63,'2018-04-09 09:42:33.681358','2018-04-09 09:42:33.681419','厨具',10),(64,'2018-04-09 09:42:44.381715','2018-04-09 09:42:44.381761','厨房卫浴',10),(65,'2018-04-09 09:43:11.880846','2018-04-09 09:43:11.880932','男装',11),(66,'2018-04-09 09:43:20.531461','2018-04-09 09:43:20.531505','女装',12),(67,'2018-04-09 09:43:32.392066','2018-04-09 09:43:32.392117','童装',13),(68,'2018-04-09 09:43:43.728460','2018-04-09 09:43:43.728501','童鞋',13),(69,'2018-04-09 09:43:52.886429','2018-04-09 09:43:52.886473','内衣',14),(70,'2018-04-09 09:44:48.786459','2018-04-09 09:44:48.786505','配饰',14),(71,'2018-04-09 09:45:52.322960','2018-04-09 09:45:52.323019','时尚女鞋',15),(72,'2018-04-09 09:46:13.344472','2018-04-09 09:46:13.344512','潮流女包',16),(73,'2018-04-09 09:46:26.135392','2018-04-09 09:46:26.135450','精品男包',16),(74,'2018-04-09 09:46:32.838944','2018-04-09 09:46:32.838985','功能箱包',16),(75,'2018-04-09 09:46:46.934480','2018-04-09 09:46:46.934544','钟表',17),(76,'2018-04-09 09:47:06.012737','2018-04-09 09:47:06.012780','珠宝首饰',18),(77,'2018-04-09 09:49:49.168425','2018-04-09 09:49:49.168465','流行男鞋',19),(78,'2018-04-09 09:49:59.855801','2018-04-09 09:49:59.855840','运动鞋包',20),(79,'2018-04-09 09:50:11.153031','2018-04-09 09:50:11.153072','运动服饰',20),(80,'2018-04-09 09:50:25.907804','2018-04-09 09:50:25.907850','健身训练',20),(81,'2018-04-09 09:50:44.505123','2018-04-09 09:50:44.505169','骑行运动',20),(82,'2018-04-09 09:50:52.703445','2018-04-09 09:50:52.703485','体育用品',20),(83,'2018-04-09 09:51:03.497014','2018-04-09 09:51:03.497061','户外鞋服',21),(84,'2018-04-09 09:51:23.359440','2018-04-09 09:51:23.359483','户外装备',21),(85,'2018-04-09 09:51:51.629105','2018-04-09 09:51:51.629160','房产',22),(86,'2018-04-09 09:52:55.706995','2018-04-09 09:52:55.707037','汽车车型',23),(87,'2018-04-09 09:53:17.292113','2018-04-09 09:53:17.292164','维修保养',23),(88,'2018-04-09 09:53:27.099413','2018-04-09 09:53:27.099455','汽车装饰',24),(89,'2018-04-09 09:53:35.047364','2018-04-09 09:53:35.047410','车载电器',24),(90,'2018-04-09 09:53:47.657176','2018-04-09 09:53:47.657269','安全自驾',24),(91,'2018-04-09 09:54:40.431814','2018-04-09 09:54:40.431856','奶粉',25),(92,'2018-04-09 09:55:00.705824','2018-04-09 09:55:00.705930','营养辅食',25),(93,'2018-04-09 09:55:31.822948','2018-04-09 09:55:31.822990','尿裤湿斤',25),(94,'2018-04-09 09:55:53.206682','2018-04-09 09:55:53.206725','玩具',26),(95,'2018-04-09 09:55:59.998048','2018-04-09 09:55:59.998088','乐器',26),(96,'2018-04-09 09:56:37.026947','2018-04-09 09:56:37.026990','新鲜水果',27),(97,'2018-04-09 09:56:47.145970','2018-04-09 09:56:47.146014','蔬菜蛋品',27),(98,'2018-04-09 09:57:06.761066','2018-04-09 09:57:06.761109','精选肉类',27),(99,'2018-04-09 09:57:18.402356','2018-04-09 09:57:18.402429','中外名酒',28),(100,'2018-04-09 09:57:32.278070','2018-04-09 09:57:32.278132','海鲜水产',29),(101,'2018-04-09 09:57:55.205251','2018-04-09 09:57:55.205317','冷饮冻食',29),(102,'2018-04-09 09:58:08.325159','2018-04-09 09:58:08.325199','地方特产',30),(103,'2018-04-09 09:59:23.347674','2018-04-09 09:59:23.347716','少儿',31),(104,'2018-04-09 09:59:41.251268','2018-04-09 09:59:41.251307','教育',31),(105,'2018-04-09 09:59:47.532578','2018-04-09 09:59:47.532627','文艺',31),(106,'2018-04-09 10:00:07.689899','2018-04-09 10:00:07.689986','音像',32),(107,'2018-04-09 10:00:15.146903','2018-04-09 10:00:15.146943','电子书',33),(108,'2018-04-09 10:00:24.463854','2018-04-09 10:00:24.463893','科技',31),(109,'2018-04-09 10:01:04.222035','2018-04-09 10:01:04.222085','交通出行',34),(110,'2018-04-09 10:01:26.371711','2018-04-09 10:01:26.371761','酒店预订',35),(111,'2018-04-09 10:01:38.237549','2018-04-09 10:01:38.237624','旅游度假',36),(112,'2018-04-09 10:01:54.257150','2018-04-09 10:01:54.257190','演出票务',37),(113,'2018-04-09 10:02:04.652269','2018-04-09 10:02:04.652320','生活缴费',37),(114,'2018-04-09 10:02:12.979008','2018-04-09 10:02:12.979053','生活服务',37),(115,'2018-04-09 10:03:27.799903','2018-04-09 10:03:27.799952','手机',38),(116,'2018-04-09 10:03:36.651429','2018-04-09 10:03:36.651502','游戏手机',38),(117,'2018-04-09 10:03:50.946486','2018-04-09 10:03:50.946530','老人机',38),(118,'2018-04-09 10:04:03.363153','2018-04-09 10:04:03.363464','对讲机',38),(119,'2018-04-09 10:04:29.550363','2018-04-09 10:04:29.550406','手机壳',39),(120,'2018-04-09 10:04:40.174739','2018-04-09 10:04:40.174807','贴膜',39),(121,'2018-04-09 10:04:49.015076','2018-04-09 10:04:49.015119','手机存储卡',39),(122,'2018-04-09 10:04:55.274758','2018-04-09 10:04:55.274991','数据线',39),(123,'2018-04-09 10:05:01.247210','2018-04-09 10:05:01.247253','充电器',39),(124,'2018-04-09 10:05:08.572487','2018-04-09 10:05:08.572568','无线充电器',39),(125,'2018-04-09 10:05:15.548216','2018-04-09 10:05:15.548283','手机耳机',39),(126,'2018-04-09 10:05:24.038601','2018-04-09 10:05:24.038668','移动电源',39),(127,'2018-04-09 10:05:33.149296','2018-04-09 10:05:33.149367','手机支架',39),(128,'2018-04-09 10:05:43.691569','2018-04-09 10:05:43.691625','数码相机',40),(129,'2018-04-09 10:06:02.872228','2018-04-09 10:06:02.872272','微单相机',40),(130,'2018-04-09 10:06:12.120240','2018-04-09 10:06:12.120292','单反相机',40),(131,'2018-04-09 10:06:24.655699','2018-04-09 10:06:24.655738','拍立得',40),(132,'2018-04-09 10:06:32.889706','2018-04-09 10:06:32.889745','运动相机',40),(133,'2018-04-09 10:06:40.857296','2018-04-09 10:06:40.857348','摄像机',40),(134,'2018-04-09 10:06:47.823916','2018-04-09 10:06:47.823964','镜头',40),(135,'2018-04-09 10:06:59.148589','2018-04-09 10:06:59.148671','数码相框',40),(136,'2018-04-09 10:07:12.634274','2018-04-09 10:07:12.634339','存储卡',41),(137,'2018-04-09 10:07:21.818264','2018-04-09 10:07:21.818310','三脚架',41),(138,'2018-04-09 10:07:47.797150','2018-04-09 10:07:47.797241','闪光灯',41),(139,'2018-04-09 10:08:05.025411','2018-04-09 10:08:05.025455','电池充电器',41),(140,'2018-04-09 10:08:14.509554','2018-04-09 10:08:14.509593','读卡器',41),(141,'2018-04-09 10:08:27.331909','2018-04-09 10:08:27.332059','耳机耳麦',42),(142,'2018-04-09 10:08:39.528114','2018-04-09 10:08:39.528322','音箱音响',42),(143,'2018-04-09 10:08:55.509999','2018-04-09 10:08:55.510276','智能音箱',42),(144,'2018-04-09 10:09:04.503537','2018-04-09 10:09:04.503583','收音机',42),(145,'2018-04-09 10:09:15.076932','2018-04-09 10:09:15.077010','麦克风',42),(146,'2018-04-09 10:09:29.493302','2018-04-09 10:09:29.493374','专业音频',42),(147,'2018-04-09 10:09:38.404834','2018-04-09 10:09:38.404878','智能手环',43),(148,'2018-04-09 10:09:47.213524','2018-04-09 10:09:47.213567','智能手表',43),(149,'2018-04-09 10:10:04.097229','2018-04-09 10:10:04.097339','智能眼镜',43),(150,'2018-04-09 10:10:10.770129','2018-04-09 10:10:10.770173','智能机器人',43),(151,'2018-04-09 10:10:32.247134','2018-04-09 10:10:32.247204','健康监测',43),(152,'2018-04-09 10:10:47.727920','2018-04-09 10:10:47.727987','学生平板',44),(153,'2018-04-09 10:11:01.757694','2018-04-09 10:11:01.757734','点读机',44),(154,'2018-04-09 10:11:46.678814','2018-04-09 10:11:46.678857','早教益智',44),(155,'2018-04-09 10:12:00.019422','2018-04-09 10:12:00.019466','电纸书',44),(156,'2018-04-09 10:12:08.762703','2018-04-09 10:12:08.762746','电子词典',44),(157,'2018-04-09 10:12:54.929293','2018-04-09 10:12:54.929354','笔记本',45),(158,'2018-04-09 10:13:12.992620','2018-04-09 10:13:12.992705','游戏本',45),(159,'2018-04-09 10:13:21.687276','2018-04-09 10:13:21.687320','平板电脑',45),(160,'2018-04-09 10:13:41.221773','2018-04-09 10:13:41.221816','台式机',45),(161,'2018-04-09 10:13:51.268043','2018-04-09 10:13:51.268533','一体机',45),(162,'2018-04-09 10:14:07.305384','2018-04-09 10:14:07.305465','工作站',45),(163,'2018-04-09 10:16:57.458227','2018-04-09 10:16:57.458275','显示器',46),(164,'2018-04-09 10:17:08.245240','2018-04-09 10:17:08.245285','CPU',46),(165,'2018-04-09 10:17:15.241497','2018-04-09 10:17:15.241614','主板',46),(166,'2018-04-09 10:17:25.695159','2018-04-09 10:17:25.695207','显卡',46),(167,'2018-04-09 10:17:35.032649','2018-04-09 10:17:35.032696','硬盘',46),(168,'2018-04-09 10:17:42.230729','2018-04-09 10:17:42.230770','内存',46),(169,'2018-04-09 10:17:50.016675','2018-04-09 10:17:50.016722','机箱',46),(170,'2018-04-09 10:17:55.578428','2018-04-09 10:17:55.578482','电源',46),(171,'2018-04-09 10:18:05.104997','2018-04-09 10:18:05.105038','散热器',46),(172,'2018-04-09 10:18:18.113135','2018-04-09 10:18:18.113185','鼠标',47),(173,'2018-04-09 10:18:26.352592','2018-04-09 10:18:26.352654','键盘',47),(174,'2018-04-09 10:18:45.584707','2018-04-09 10:18:45.584746','键鼠套装',47),(175,'2018-04-09 10:18:54.592085','2018-04-09 10:18:54.592146','U盘',47),(176,'2018-04-09 10:19:02.774592','2018-04-09 10:19:02.774644','移动硬盘',47),(177,'2018-04-09 10:19:29.344648','2018-04-09 10:19:29.344688','鼠标垫',47),(178,'2018-04-09 10:20:01.647599','2018-04-09 10:20:01.647652','摄像头',47),(179,'2018-04-09 10:20:10.633329','2018-04-09 10:20:10.633371','线缆',47),(180,'2018-04-09 10:20:29.108708','2018-04-09 10:20:29.108750','手写板',47),(181,'2018-04-09 10:20:50.965054','2018-04-09 10:20:50.965110','投影机',48),(182,'2018-04-09 10:21:11.973042','2018-04-09 10:21:11.973085','投影配件',48),(183,'2018-04-09 10:28:38.875264','2018-04-09 10:28:38.875323','多功能一体机',48),(184,'2018-04-09 10:28:58.044119','2018-04-09 10:28:58.044161','打印机',48),(185,'2018-04-09 10:29:24.286741','2018-04-09 10:29:24.286786','硒鼓墨粉',49),(186,'2018-04-09 10:29:32.433762','2018-04-09 10:29:32.433832','墨盒',49),(187,'2018-04-09 10:29:40.185494','2018-04-09 10:29:40.185535','色带',49),(188,'2018-04-09 10:29:51.285563','2018-04-09 10:29:51.285630','纸类',49),(189,'2018-04-09 10:30:02.125287','2018-04-09 10:30:02.125326','办公文具',49),(190,'2018-04-09 10:30:13.747314','2018-04-09 10:30:13.747366','文件收纳',49),(191,'2018-04-09 10:30:25.486463','2018-04-09 10:30:25.486503','计算器',49),(192,'2018-04-09 10:30:33.569198','2018-04-09 10:30:33.569262','笔类',49),(197,'2018-04-09 10:31:30.282436','2018-04-09 10:31:30.282480','壁挂式空调',51),(198,'2018-04-09 10:31:46.070209','2018-04-09 10:31:46.070256','柜式空调',51),(199,'2018-04-09 10:31:53.705108','2018-04-09 10:31:53.705152','中央空调',51),(200,'2018-04-09 10:32:02.828470','2018-04-09 10:32:02.828512','节能空调',51),(201,'2018-04-09 10:32:10.699372','2018-04-09 10:32:10.699438','智能空调',51),(202,'2018-04-09 10:32:21.537627','2018-04-09 10:32:21.537671','滚筒洗衣机',52),(203,'2018-04-09 10:32:40.271821','2018-04-09 10:32:40.271865','洗烘一体机',52),(204,'2018-04-09 10:33:07.290966','2018-04-09 10:33:07.291127','波轮洗衣机',52),(205,'2018-04-09 10:33:17.913196','2018-04-09 10:33:17.913237','迷你洗衣机',52),(206,'2018-04-09 10:33:30.617336','2018-04-09 10:33:30.617428','多门',53),(207,'2018-04-09 10:35:16.138738','2018-04-09 10:35:16.138781','对开门',53),(208,'2018-04-09 10:35:27.196414','2018-04-09 10:35:27.196483','三门',53),(209,'2018-04-09 10:35:35.870793','2018-04-09 10:35:35.870876','双门',53),(215,'2018-04-09 10:44:09.292409','2018-04-09 10:44:09.292481','空气净化器',55),(216,'2018-04-09 10:44:21.773107','2018-04-09 10:44:21.773185','电风扇',55),(217,'2018-04-09 10:44:30.623621','2018-04-09 10:44:30.623668','扫地机器人',55),(218,'2018-04-09 10:44:47.127513','2018-04-09 10:44:47.127554','拖地机',55),(219,'2018-04-09 10:44:57.367766','2018-04-09 10:44:57.367812','干衣机',55),(220,'2018-04-09 10:45:05.140806','2018-04-09 10:45:05.140845','电话机',55),(221,'2018-04-09 10:45:43.383869','2018-04-09 10:45:43.383911','收纳用品',56),(222,'2018-04-09 10:45:55.997898','2018-04-09 10:45:55.997945','雨伞雨具',56),(223,'2018-04-09 10:46:11.700313','2018-04-09 10:46:11.700382','净化除味',56),(224,'2018-04-09 10:46:21.798864','2018-04-09 10:46:21.798963','浴室用品',56),(225,'2018-04-09 10:46:38.851705','2018-04-09 10:46:38.851744','缝纫针织',56),(226,'2018-04-09 10:47:29.768792','2018-04-09 10:47:29.768851','床品套件',57),(227,'2018-04-09 10:47:43.068195','2018-04-09 10:47:43.068238','被子',57),(228,'2018-04-09 10:47:55.954652','2018-04-09 10:47:55.954704','枕芯',57),(229,'2018-04-09 10:48:07.054248','2018-04-09 10:48:07.054299','蚊帐',57),(230,'2018-04-09 10:48:13.148110','2018-04-09 10:48:13.148207','凉席',57),(231,'2018-04-09 10:48:22.983566','2018-04-09 10:48:22.983608','毛巾浴巾',57),(232,'2018-04-09 10:48:40.536740','2018-04-09 10:48:40.537102','吸顶灯',58),(233,'2018-04-09 10:48:49.011808','2018-04-09 10:48:49.011852','吊灯',58),(234,'2018-04-09 10:48:57.503376','2018-04-09 10:48:57.503551','台灯',58),(235,'2018-04-09 10:49:09.990632','2018-04-09 10:49:09.990674','筒灯射灯',58),(236,'2018-04-09 10:49:19.476924','2018-04-09 10:49:19.476970','装饰灯',58),(237,'2018-04-09 10:49:34.463529','2018-04-09 10:49:34.463587','卧室家具',59),(238,'2018-04-09 10:49:43.863760','2018-04-09 10:49:43.863805','客厅家具',59),(239,'2018-04-09 10:49:52.890521','2018-04-09 10:49:52.890566','餐厅家具',59),(240,'2018-04-09 10:50:00.371566','2018-04-09 10:50:00.371818','书房家具',59),(241,'2018-04-09 10:50:07.098922','2018-04-09 10:50:07.098961','儿童家具',59),(242,'2018-04-09 10:50:19.143462','2018-04-09 10:50:19.143527','装饰字画',60),(243,'2018-04-09 10:50:26.723524','2018-04-09 10:50:26.723568','装饰摆件',60),(244,'2018-04-09 10:50:37.529642','2018-04-09 10:50:37.529683','十字绣',60),(245,'2018-04-09 10:51:02.366545','2018-04-09 10:51:02.366585','墙贴',60),(246,'2018-04-09 10:51:14.673577','2018-04-09 10:51:14.673622','瓷砖',61),(247,'2018-04-09 10:51:20.529141','2018-04-09 10:51:20.529261','地板',61),(248,'2018-04-09 10:51:31.121585','2018-04-09 10:51:31.121641','油漆涂料',61),(249,'2018-04-09 10:51:39.261015','2018-04-09 10:51:39.261077','壁纸',61),(250,'2018-04-09 10:52:03.520983','2018-04-09 10:52:03.521024','锁具',62),(251,'2018-04-09 10:52:12.470392','2018-04-09 10:52:12.470482','电动工具',62),(252,'2018-04-09 10:52:21.041130','2018-04-09 10:52:21.041174','手动工具',62),(253,'2018-04-09 10:52:31.599209','2018-04-09 10:52:31.599255','测量工具',62),(254,'2018-04-09 10:52:49.673907','2018-04-09 10:52:49.673945','劳防用品',62),(255,'2018-04-09 10:53:22.230127','2018-04-09 10:53:22.230194','水具酒具',63),(256,'2018-04-09 10:53:36.874892','2018-04-09 10:53:36.874935','烹饪锅具',63),(257,'2018-04-09 10:53:46.025047','2018-04-09 10:53:46.025129','餐具',63),(258,'2018-04-09 10:53:59.183741','2018-04-09 10:53:59.183788','厨房配件',63),(259,'2018-04-09 10:54:17.154351','2018-04-09 10:54:17.154409','刀剪菜板',63),(260,'2018-04-09 10:54:28.054467','2018-04-09 10:54:28.054511','锅具套装',63),(261,'2018-04-09 10:54:39.436215','2018-04-09 10:54:39.436460','水槽',64),(262,'2018-04-09 10:54:48.490520','2018-04-09 10:54:48.490561','龙头',64),(263,'2018-04-09 10:54:58.615841','2018-04-09 10:54:58.616299','淋浴花洒',64),(264,'2018-04-09 10:55:07.214304','2018-04-09 10:55:07.214363','马桶',64),(265,'2018-04-09 10:55:24.453550','2018-04-09 10:55:24.453593','厨卫挂件',64),(266,'2018-04-09 10:55:37.042973','2018-04-09 10:55:37.043014','浴室柜',64),(267,'2018-04-09 10:55:58.093400','2018-04-09 10:55:58.093487','T恤',65),(268,'2018-04-09 10:56:06.167659','2018-04-09 10:56:06.167702','牛仔裤',65),(269,'2018-04-09 10:56:15.579739','2018-04-09 10:56:15.579781','衬衫',65),(270,'2018-04-09 10:56:21.330228','2018-04-09 10:56:21.330268','短裤',65),(271,'2018-04-09 10:56:31.432431','2018-04-09 10:56:31.432506','羽绒服',65),(272,'2018-04-09 10:56:45.065922','2018-04-09 10:56:45.065962','卫衣',65),(273,'2018-04-09 10:57:07.546075','2018-04-09 10:57:07.546116','西服套装',65),(274,'2018-04-09 10:57:18.823678','2018-04-09 10:57:18.823720','衬衫',66),(275,'2018-04-09 10:57:41.556178','2018-04-09 10:57:41.556225','雪纺衫',66),(276,'2018-04-09 10:57:52.929657','2018-04-09 10:57:52.929697','短衣套',66),(277,'2018-04-09 10:57:59.657898','2018-04-09 10:57:59.657943','卫衣',66),(278,'2018-04-09 10:58:07.246701','2018-04-09 10:58:07.246743','休闲裤',66),(279,'2018-04-09 10:58:17.075213','2018-04-09 10:58:17.075255','牛仔裤',66),(280,'2018-04-09 10:58:28.783506','2018-04-09 10:58:28.783624','小西装',66),(281,'2018-04-09 10:58:39.734123','2018-04-09 10:58:39.734165','套装',67),(282,'2018-04-09 10:58:54.035921','2018-04-09 10:58:54.035999','卫衣',67),(283,'2018-04-09 10:59:01.809045','2018-04-09 10:59:01.809112','裤子',67),(284,'2018-04-09 10:59:11.529237','2018-04-09 10:59:11.529278','衬衫',67),(285,'2018-04-09 10:59:19.701142','2018-04-09 10:59:19.701182','羽绒服',67),(286,'2018-04-09 10:59:29.917807','2018-04-09 10:59:29.917935','棉服',67),(287,'2018-04-09 10:59:37.808649','2018-04-09 10:59:37.808697','内衣裤',67),(288,'2018-04-09 10:59:47.335110','2018-04-09 10:59:47.335153','运动鞋',68),(289,'2018-04-09 10:59:55.048010','2018-04-09 10:59:55.048115','靴子',68),(290,'2018-04-09 11:00:01.655226','2018-04-09 11:00:01.655389','帆布鞋',68),(291,'2018-04-09 11:00:10.050759','2018-04-09 11:00:10.050847','棉鞋',68),(292,'2018-04-09 11:00:36.252685','2018-04-09 11:00:36.252727','睡衣',69),(293,'2018-04-09 11:00:51.916631','2018-04-09 11:00:51.916725','打底裤',69),(294,'2018-04-09 11:01:03.507003','2018-04-09 11:01:03.507082','保暖内衣',69),(295,'2018-04-09 11:01:17.165081','2018-04-09 11:01:17.165123','背心',69),(296,'2018-04-09 11:01:27.044001','2018-04-09 11:01:27.044043','男士内裤',69),(297,'2018-04-09 11:01:36.242881','2018-04-09 11:01:36.242924','女士内裤',69),(298,'2018-04-09 11:01:54.834481','2018-04-09 11:01:54.834524','披肩',70),(299,'2018-04-09 11:02:00.645511','2018-04-09 11:02:00.645551','围巾',70),(300,'2018-04-09 11:02:11.482667','2018-04-09 11:02:11.482721','镜片',70),(301,'2018-04-09 11:02:20.022779','2018-04-09 11:02:20.022826','太阳镜',70),(302,'2018-04-09 11:02:34.084449','2018-04-09 11:02:34.084490','毛线帽',70),(303,'2018-04-09 11:02:46.119130','2018-04-09 11:02:46.119177','礼貌',70),(304,'2018-04-09 11:02:58.516680','2018-04-09 11:02:58.516821','口罩',70),(305,'2018-04-09 11:03:18.478719','2018-04-09 11:03:18.478762','单鞋',71),(306,'2018-04-09 11:03:34.487317','2018-04-09 11:03:34.487363','休闲鞋',71),(307,'2018-04-09 11:03:43.157761','2018-04-09 11:03:43.157841','帆布鞋',71),(308,'2018-04-09 11:03:52.414196','2018-04-09 11:03:52.414241','妈妈鞋',71),(309,'2018-04-09 11:04:07.541405','2018-04-09 11:04:07.541475','女靴',71),(310,'2018-04-09 11:04:21.823807','2018-04-09 11:04:21.823863','高跟鞋',71),(311,'2018-04-09 11:04:33.148296','2018-04-09 11:04:33.148342','凉鞋',71),(312,'2018-04-09 11:04:42.712939','2018-04-09 11:04:42.712979','真皮包',72),(313,'2018-04-09 11:05:01.537643','2018-04-09 11:05:01.537695','单肩包',72),(314,'2018-04-09 11:05:10.452996','2018-04-09 11:05:10.453036','手提包',72),(315,'2018-04-09 11:05:21.516678','2018-04-09 11:05:21.516722','鞋挎包',72),(316,'2018-04-09 11:18:13.518247','2018-04-09 11:18:13.518288','双肩包',72),(317,'2018-04-09 11:18:24.704274','2018-04-09 11:18:24.704314','钱包',72),(318,'2018-04-09 11:21:41.102117','2018-04-09 11:21:41.102167','男士钱包',73),(319,'2018-04-09 11:21:51.040168','2018-04-09 11:21:51.040272','双肩包',73),(320,'2018-04-09 11:22:20.721731','2018-04-09 11:22:20.721812','单肩包',73),(321,'2018-04-09 11:22:37.133514','2018-04-09 11:22:37.133556','商务公文包',73),(322,'2018-04-09 11:22:51.040191','2018-04-09 11:22:51.040233','男士手包',73),(323,'2018-04-09 11:24:09.390104','2018-04-09 11:24:09.390170','拉杆箱',74),(324,'2018-04-09 11:24:20.905499','2018-04-09 11:24:20.905542','拉杆包',74),(325,'2018-04-09 11:24:38.908847','2018-04-09 11:24:38.908888','旅行包',74),(326,'2018-04-09 11:24:59.546666','2018-04-09 11:24:59.546709','电脑包',74),(327,'2018-04-09 11:25:09.425172','2018-04-09 11:25:09.425223','休闲运动包',74),(328,'2018-04-09 11:25:17.336990','2018-04-09 11:25:17.337047','书包',74),(329,'2018-04-09 11:25:29.965879','2018-04-09 11:25:29.965945','登山包',74),(330,'2018-04-09 11:25:56.939364','2018-04-09 11:25:56.939402','天梭',75),(331,'2018-04-09 11:26:13.919984','2018-04-09 11:26:13.920027','浪琴',75),(332,'2018-04-09 11:26:51.898328','2018-04-09 11:26:51.898506','欧米茄',75),(333,'2018-04-09 11:27:09.494057','2018-04-09 11:27:09.494120','泰格豪雅',75),(334,'2018-04-09 11:27:15.382732','2018-04-09 11:27:15.382833','DW',75),(335,'2018-04-09 11:27:24.784177','2018-04-09 11:27:24.784225','卡西欧',75),(336,'2018-04-09 11:27:31.447596','2018-04-09 11:27:31.447669','西铁城',75),(337,'2018-04-09 11:27:42.642805','2018-04-09 11:27:42.642852','黄金',76),(338,'2018-04-09 11:27:49.327614','2018-04-09 11:27:49.327665','K金',76),(339,'2018-04-09 11:28:01.614654','2018-04-09 11:28:01.614700','时尚饰品',76),(340,'2018-04-09 11:28:09.412255','2018-04-09 11:28:09.412299','钻石',76),(341,'2018-04-09 11:28:22.916617','2018-04-09 11:28:22.916662','翡翠玉石',76),(342,'2018-04-09 11:28:30.345615','2018-04-09 11:28:30.345663','银饰',76),(343,'2018-04-09 11:28:39.321423','2018-04-09 11:28:39.321477','水晶玛瑙',76),(344,'2018-04-09 11:28:57.657591','2018-04-09 11:28:57.657636','休闲鞋',77),(345,'2018-04-09 12:08:16.560944','2018-04-11 12:37:00.856809','商务休闲鞋',77),(346,'2018-04-09 12:09:27.344880','2018-04-09 12:09:27.344924','正装鞋',77),(347,'2018-04-09 12:09:36.131127','2018-04-09 12:09:36.131175','帆布鞋',77),(348,'2018-04-09 12:09:46.733096','2018-04-09 12:09:46.733135','凉鞋',77),(349,'2018-04-09 12:10:12.669806','2018-04-09 12:10:12.669851','跑步鞋',78),(350,'2018-04-09 12:10:24.462717','2018-04-09 12:10:24.462757','休闲鞋',78),(351,'2018-04-09 12:10:33.369187','2018-04-09 12:10:33.369266','篮球鞋',78),(352,'2018-04-09 12:10:41.678099','2018-04-09 12:10:41.678147','帆布鞋',77),(353,'2018-04-09 12:10:52.832621','2018-04-09 12:10:52.832671','板鞋',77),(354,'2018-04-09 12:11:11.611198','2018-04-09 12:11:11.611250','拖鞋',78),(355,'2018-04-09 12:11:20.463957','2018-04-09 12:11:20.464001','运动包',78),(356,'2018-04-09 12:11:37.214241','2018-04-09 12:11:37.214291','足球鞋',78),(357,'2018-04-09 12:13:15.915511','2018-04-09 12:13:15.915579','T恤',79),(358,'2018-04-09 12:13:38.332607','2018-04-09 12:13:38.332682','运动套装',79),(359,'2018-04-09 12:13:48.314684','2018-04-09 12:13:48.314757','运动裤',79),(360,'2018-04-09 12:13:58.115856','2018-04-09 12:13:58.115930','卫衣',79),(361,'2018-04-09 12:14:05.741448','2018-04-09 12:14:05.741497','夹克',79),(362,'2018-04-09 12:14:13.258943','2018-04-09 12:14:13.258986','羽绒服',79),(363,'2018-04-09 12:14:44.556933','2018-04-09 12:14:44.556986','跑步机',80),(364,'2018-04-09 12:15:14.348396','2018-04-09 12:15:14.348504','动感单车',80),(365,'2018-04-09 12:15:25.182779','2018-04-09 12:15:25.182818','健身车',80),(366,'2018-04-09 12:15:39.011764','2018-04-09 12:15:39.011803','椭圆机',80),(367,'2018-04-09 12:15:52.191090','2018-04-09 12:15:52.191133','综合训练器',80),(368,'2018-04-09 12:16:00.759984','2018-04-09 12:16:00.760022','划船机',80),(369,'2018-04-09 12:16:23.743936','2018-04-09 12:16:23.743975','甩脂机',80),(370,'2018-04-09 12:16:37.158374','2018-04-09 12:16:37.158419','山地车',81),(371,'2018-04-09 12:16:47.227313','2018-04-09 12:16:47.227353','公路车',81),(372,'2018-04-09 12:16:54.949681','2018-04-09 12:16:54.949725','折叠车',81),(373,'2018-04-09 12:17:05.820361','2018-04-09 12:17:05.820407','骑行服',81),(374,'2018-04-09 12:17:13.605959','2018-04-09 12:17:13.606000','电动车',81),(375,'2018-04-09 12:17:33.944309','2018-04-09 12:17:33.944412','电动滑板车',81),(376,'2018-04-09 12:17:50.672612','2018-04-09 12:17:50.672823','乒乓球',82),(377,'2018-04-09 12:18:02.249051','2018-04-09 12:18:02.249115','羽毛球',81),(378,'2018-04-09 12:18:17.658163','2018-04-09 12:18:32.143808','篮球',82),(379,'2018-04-09 12:18:44.169275','2018-04-09 12:18:44.169314','足球',82),(380,'2018-04-09 12:18:59.052389','2018-04-09 12:18:59.052430','轮滑滑板',82),(381,'2018-04-09 12:19:13.369855','2018-04-09 12:19:13.369895','网球',82),(382,'2018-04-09 12:19:20.514040','2018-04-09 12:19:20.514088','高尔夫',82),(383,'2018-04-09 12:19:41.478550','2018-04-09 12:19:41.478590','户外风衣',83),(384,'2018-04-09 12:19:50.948351','2018-04-09 12:19:50.948402','徒步鞋',83),(385,'2018-04-09 12:20:00.773041','2018-04-09 12:20:00.773107','T恤',83),(386,'2018-04-09 12:20:13.572677','2018-04-09 12:20:13.572731','冲锋衣裤',83),(387,'2018-04-09 12:20:35.830642','2018-04-09 12:20:35.830691','速干衣裤',83),(388,'2018-04-09 12:20:45.236874','2018-04-09 12:20:45.236916','越野跑鞋',83),(389,'2018-04-09 12:20:53.484799','2018-04-09 12:20:53.484931','滑雪服',83),(390,'2018-04-09 12:21:03.664043','2018-04-09 12:21:03.664087','背包',84),(391,'2018-04-09 12:21:13.588552','2018-04-09 12:21:13.588761','帐篷',84),(392,'2018-04-09 12:21:22.627360','2018-04-09 12:21:22.627441','望远镜',84),(393,'2018-04-09 12:21:31.571427','2018-04-09 12:21:31.571470','烧烤用具',84),(394,'2018-04-09 12:21:43.436347','2018-04-09 12:21:43.436386','编写桌椅床',84),(395,'2018-04-09 12:21:51.496392','2018-04-09 12:21:51.496432','户外配饰',84),(396,'2018-04-09 12:22:03.144795','2018-04-09 12:22:03.144838','军迷用品',84),(397,'2018-04-09 12:22:19.174208','2018-04-09 12:22:19.174256','最新开盘',85),(398,'2018-04-09 12:22:32.680341','2018-04-09 12:22:32.680381','普通住宅',85),(399,'2018-04-09 12:23:13.036354','2018-04-09 12:23:13.036402','别墅',85),(400,'2018-04-09 12:23:20.661348','2018-04-09 12:23:20.661400','商业办公',85),(401,'2018-04-09 12:23:32.836788','2018-04-09 12:23:32.836830','海外房产',85),(402,'2018-04-09 12:23:47.819951','2018-04-09 12:23:47.820002','微型车',86),(403,'2018-04-09 12:23:56.486888','2018-04-09 12:23:56.486929','小型车',86),(404,'2018-04-09 12:24:09.346459','2018-04-09 12:24:09.346508','紧凑型车',86),(405,'2018-04-09 12:24:23.609500','2018-04-09 12:24:23.609542','中型车',86),(406,'2018-04-09 12:24:34.464050','2018-04-09 12:24:34.464093','中大行车',86),(407,'2018-04-09 12:24:46.157301','2018-04-09 12:24:46.157342','机油',87),(408,'2018-04-09 12:24:54.173351','2018-04-09 12:24:54.173391','轮胎',87),(409,'2018-04-09 12:25:01.636545','2018-04-09 12:25:01.636588','添加剂',87),(410,'2018-04-09 12:25:13.324702','2018-04-09 12:25:13.324750','防冻液',87),(411,'2018-04-09 12:25:23.875459','2018-04-09 12:25:23.875500','滤清器',87),(412,'2018-04-09 12:25:35.605448','2018-04-09 12:25:35.605489','蓄电池',87),(413,'2018-04-09 12:25:48.272607','2018-04-09 12:25:48.272647','雨刷',87),(414,'2018-04-09 12:26:04.737314','2018-04-09 12:26:04.737356','座垫座套',88),(415,'2018-04-09 12:26:25.466016','2018-04-09 12:26:25.466060','脚垫',88),(416,'2018-04-09 12:26:41.636108','2018-04-09 12:26:41.636148','头枕腰靠',88),(417,'2018-04-09 12:26:50.317697','2018-04-09 12:26:50.317737','方向盘套',88),(418,'2018-04-09 12:27:04.852657','2018-04-09 12:27:04.852698','后备箱垫',88),(419,'2018-04-09 12:27:28.245163','2018-04-09 12:27:28.245206','车载支架',88),(420,'2018-04-09 12:27:42.249996','2018-04-09 12:27:42.250040','挂件摆件',88),(421,'2018-04-09 12:27:56.558508','2018-04-09 12:27:56.558549','行车记录仪',89),(422,'2018-04-09 12:28:07.738113','2018-04-09 12:28:07.738158','车载充电器',89),(423,'2018-04-09 12:28:20.669977','2018-04-09 12:28:20.670037','车机导航',89),(424,'2018-04-09 12:28:30.768756','2018-04-09 12:28:30.768865','车载蓝牙',89),(425,'2018-04-09 12:28:40.911231','2018-04-09 12:28:40.911300','智能驾驶',89),(426,'2018-04-09 12:28:50.264210','2018-04-09 12:28:50.264251','车载净化器',89),(427,'2018-04-09 12:29:05.698627','2018-04-09 12:29:05.698671','车载吸尘器',89),(428,'2018-04-09 12:29:21.396287','2018-04-09 12:29:21.396347','胎压监测',90),(429,'2018-04-09 12:29:29.941158','2018-04-09 12:29:29.941199','充气泵',90),(430,'2018-04-09 12:29:38.039932','2018-04-09 12:29:38.039976','灭火器',90),(431,'2018-04-09 12:29:45.055847','2018-04-09 12:29:45.055888','车载床',90),(432,'2018-04-09 12:29:53.265950','2018-04-09 12:29:53.265998','应急救援',90),(433,'2018-04-09 12:30:04.204188','2018-04-09 12:30:04.204227','防盗设备',90),(434,'2018-04-09 12:30:21.022724','2018-04-09 12:30:21.022771','1段',91),(435,'2018-04-09 12:30:28.705125','2018-04-09 12:30:28.705297','2段',91),(436,'2018-04-09 12:30:41.640737','2018-04-09 12:30:41.640777','3段',91),(437,'2018-04-09 12:30:47.938600','2018-04-09 12:30:47.938654','4段',91),(438,'2018-04-09 12:31:01.503065','2018-04-09 12:31:01.503251','孕妈奶粉',91),(439,'2018-04-09 12:31:10.862232','2018-04-09 12:31:10.862287','有机奶粉',91),(440,'2018-04-09 12:31:20.344400','2018-04-09 12:31:20.344443','米粉',92),(441,'2018-04-09 12:31:30.706523','2018-04-09 12:31:30.706688','面条',92),(442,'2018-04-09 12:31:44.035896','2018-04-09 12:31:44.035975','果泥',92),(443,'2018-04-09 12:31:57.403136','2018-04-09 12:31:57.403180','益生菌',92),(444,'2018-04-09 12:32:10.384580','2018-04-09 12:32:10.384629','DHA',92),(445,'2018-04-09 12:32:21.916098','2018-04-09 12:32:21.916144','NB',93),(446,'2018-04-09 12:32:29.287475','2018-04-09 12:32:29.287523','S',93),(447,'2018-04-09 12:32:36.424841','2018-04-09 12:32:36.424887','M',93),(448,'2018-04-09 12:32:42.132988','2018-04-09 12:32:42.133030','L',93),(449,'2018-04-09 12:32:50.778168','2018-04-09 12:32:50.778233','XL',93),(450,'2018-04-09 12:32:57.068461','2018-04-09 12:32:57.068502','XXL',93),(451,'2018-04-09 12:33:06.777164','2018-04-09 12:33:06.777211','拉拉裤',93),(452,'2018-04-09 12:33:24.613039','2018-04-09 12:33:24.613080','遥控电动',94),(453,'2018-04-09 12:33:31.652664','2018-04-09 12:33:31.652732','益智玩具',94),(454,'2018-04-09 12:33:45.339728','2018-04-09 12:33:45.339766','积木拼插',94),(455,'2018-04-09 12:33:55.126028','2018-04-09 12:33:55.126067','动漫玩具',94),(456,'2018-04-09 12:34:11.655807','2018-04-09 12:34:11.655851','毛绒布艺',94),(457,'2018-04-09 12:34:20.900620','2018-04-09 12:34:20.900691','钢琴',95),(458,'2018-04-09 12:34:28.181696','2018-04-09 12:34:28.181746','电钢琴',95),(459,'2018-04-09 12:34:39.033787','2018-04-09 12:34:39.033837','电子琴',95),(460,'2018-04-09 12:34:44.586005','2018-04-09 12:34:44.586048','吉他',95),(461,'2018-04-09 12:35:00.803528','2018-04-09 12:35:00.803568','尤克里里',95),(462,'2018-04-09 12:35:17.639608','2018-04-09 12:35:17.639654','苹果',96),(463,'2018-04-09 12:35:24.396253','2018-04-09 12:35:24.396333','香蕉',96),(464,'2018-04-09 12:35:38.853589','2018-04-09 12:35:38.853630','梨',96),(465,'2018-04-09 12:35:44.700034','2018-04-09 12:35:44.700076','橙子',96),(466,'2018-04-09 12:35:54.523749','2018-04-09 12:35:54.523791','奇异果',96),(467,'2018-04-09 12:36:04.893146','2018-04-09 12:36:04.893199','火龙果',96),(468,'2018-04-09 12:36:14.484152','2018-04-09 12:36:14.485197','蛋品',97),(469,'2018-04-09 12:36:28.415979','2018-04-09 12:36:28.416033','叶菜类',97),(470,'2018-04-09 12:36:37.316846','2018-04-09 12:36:37.316905','根茎类',97),(471,'2018-04-09 12:36:56.682895','2018-04-09 12:36:56.682936','葱姜蒜椒',97),(472,'2018-04-09 12:37:09.086730','2018-04-09 12:37:09.086801','猪肉',98),(473,'2018-04-09 12:37:14.763994','2018-04-09 12:37:14.764035','牛肉',98),(474,'2018-04-09 12:37:23.722896','2018-04-09 12:37:23.722937','羊肉',98),(475,'2018-04-09 12:37:31.952876','2018-04-09 12:37:31.952917','鸡肉',98),(476,'2018-04-09 12:37:40.185669','2018-04-09 12:37:40.185708','鸭肉',98),(477,'2018-04-09 12:37:54.541087','2018-04-09 12:37:54.541206','白酒',99),(478,'2018-04-09 12:38:00.476058','2018-04-09 12:38:00.476103','葡萄酒',99),(479,'2018-04-09 12:38:07.401633','2018-04-09 12:38:07.401673','洋酒',99),(480,'2018-04-09 12:38:15.374182','2018-04-09 12:38:15.374237','啤酒',99),(481,'2018-04-09 12:38:22.161741','2018-04-09 12:38:22.162162','黄酒',99),(482,'2018-04-09 12:38:34.069996','2018-04-09 12:38:34.070069','鱼类',100),(483,'2018-04-09 12:38:40.454694','2018-04-09 12:38:40.454748','虾类',100),(484,'2018-04-09 12:38:50.430100','2018-04-09 12:38:50.430144','蟹类',100),(485,'2018-04-09 12:38:59.664340','2018-04-09 12:38:59.664378','贝类',100),(486,'2018-04-09 12:39:07.324234','2018-04-09 12:39:07.324272','海参',100),(487,'2018-04-09 12:39:17.066508','2018-04-09 12:39:17.066561','鱿鱼',100),(488,'2018-04-09 12:39:24.459066','2018-04-09 12:39:24.459109','水饺',101),(489,'2018-04-09 12:39:34.604818','2018-04-09 12:39:34.604873','汤圆',101),(490,'2018-04-09 12:39:41.951256','2018-04-09 12:39:41.951389','面点',101),(491,'2018-04-09 12:39:56.644602','2018-04-09 12:39:56.644666','烘培半成品',101),(492,'2018-04-09 12:40:06.995033','2018-04-09 12:40:06.995079','方便速食',101),(493,'2018-04-09 12:40:18.989451','2018-04-09 12:40:18.989491','华北',102),(494,'2018-04-09 12:40:24.498405','2018-04-09 12:40:24.498446','华东',102),(495,'2018-04-09 12:40:35.291572','2018-04-09 12:40:35.291613','华南',102),(496,'2018-04-09 12:40:44.577503','2018-04-09 12:40:44.577596','华中',102),(497,'2018-04-09 12:40:50.353640','2018-04-09 12:40:50.353719','东北',102),(498,'2018-04-09 12:40:59.948664','2018-04-09 12:40:59.948705','西北',102),(499,'2018-04-09 12:41:04.991165','2018-04-09 12:41:04.991210','西南',102),(500,'2018-04-09 12:41:20.415788','2018-04-09 12:41:33.490500','0-2岁',103),(501,'2018-04-09 12:41:51.393210','2018-04-09 12:41:51.393266','3-6岁',103),(502,'2018-04-09 12:42:00.521776','2018-04-09 12:42:00.521834','7-10岁',103),(503,'2018-04-09 12:42:06.853828','2018-04-09 12:42:06.853879','11-14岁',103),(504,'2018-04-09 12:42:15.217304','2018-04-09 12:42:15.217346','儿童文艺',103),(505,'2018-04-09 12:42:21.085464','2018-04-09 12:42:21.085572','绘本',103),(506,'2018-04-09 12:42:26.635396','2018-04-09 12:42:26.635436','科普',103),(507,'2018-04-09 12:42:35.299418','2018-04-09 12:42:35.299457','教材',104),(508,'2018-04-09 12:42:44.941114','2018-04-09 12:42:44.941153','中小学教辅',104),(509,'2018-04-09 12:42:51.391709','2018-04-09 12:42:51.391751','考试',104),(510,'2018-04-09 12:43:03.953751','2018-04-09 12:43:03.953795','外语学习',104),(511,'2018-04-09 12:43:13.404857','2018-04-09 12:43:13.404902','字典词典',104),(512,'2018-04-09 12:43:22.635176','2018-04-09 12:43:22.635220','小说',105),(513,'2018-04-09 12:43:29.185733','2018-04-09 12:43:29.185956','文学',105),(514,'2018-04-09 12:43:36.123019','2018-04-09 12:43:36.123619','青春文学',105),(515,'2018-04-09 12:43:57.373715','2018-04-09 12:43:57.373760','传记',105),(516,'2018-04-09 12:44:02.905921','2018-04-09 12:44:02.905961','动漫',105),(517,'2018-04-09 12:44:10.930632','2018-04-09 12:44:10.930677','艺术',105),(518,'2018-04-09 12:44:22.797355','2018-04-09 12:44:22.797407','音乐',106),(519,'2018-04-09 12:44:29.689156','2018-04-09 12:44:29.689196','影视',106),(520,'2018-04-09 12:44:41.896114','2018-04-09 12:44:41.896156','教育音像',106),(521,'2018-04-09 12:44:52.139493','2018-04-09 12:44:52.139567','游戏',106),(522,'2018-04-09 12:45:04.183430','2018-04-09 12:45:04.183788','小说',107),(523,'2018-04-09 12:45:12.853989','2018-04-09 12:45:12.854064','励志与成功',107),(524,'2018-04-09 12:45:20.095013','2018-04-09 12:45:20.095176','经济金融',107),(525,'2018-04-09 12:45:29.048014','2018-04-09 12:45:29.048060','文学',107),(526,'2018-04-09 12:45:45.137162','2018-04-09 12:45:45.137200','计算机与互联网',108),(527,'2018-04-09 12:45:55.864096','2018-04-09 12:45:55.864135','科普',108),(528,'2018-04-09 12:46:02.495930','2018-04-09 12:46:02.495974','建筑',108),(529,'2018-04-09 12:46:12.225136','2018-04-09 12:46:12.225451','工业技术',108),(530,'2018-04-09 12:46:22.281103','2018-04-09 12:46:22.281142','电子通信',108),(531,'2018-04-09 12:46:28.058464','2018-04-09 12:46:28.058510','医学',108),(532,'2018-04-09 12:46:34.969122','2018-04-09 12:46:34.969166','农林',108),(533,'2018-04-09 12:46:50.460306','2018-04-09 12:46:50.460367','国内机票',109),(534,'2018-04-09 12:47:03.136221','2018-04-09 12:47:03.136285','国际机票',109),(535,'2018-04-09 12:47:08.441450','2018-04-09 12:47:08.441508','火车票',109),(536,'2018-04-09 12:47:15.969474','2018-04-09 12:47:15.969514','机场服务',109),(537,'2018-04-09 12:47:27.075057','2018-04-09 12:47:27.075338','国内酒店',110),(538,'2018-04-09 12:47:37.048895','2018-04-09 12:47:37.048936','国际酒店',110),(539,'2018-04-09 12:47:49.230938','2018-04-09 12:47:49.230980','超值精选酒店',110),(540,'2018-04-09 12:47:59.488914','2018-04-09 12:47:59.488958','国内旅游',111),(541,'2018-04-09 12:48:13.464137','2018-04-09 12:48:13.464184','出境旅游',111),(542,'2018-04-09 12:48:25.847481','2018-04-09 12:48:25.847528','景点门票',111),(543,'2018-04-09 12:48:43.599292','2018-04-09 12:48:43.599333','电影选座',112),(544,'2018-04-09 12:49:00.580843','2018-04-09 12:49:00.580886','演唱会',112),(545,'2018-04-09 12:49:09.886332','2018-04-09 12:49:09.886374','音乐会',112),(546,'2018-04-09 12:49:24.549168','2018-04-09 12:49:24.549214','话剧歌剧',112),(547,'2018-04-09 12:49:31.673625','2018-04-09 12:49:31.673733','体育赛事',112),(548,'2018-04-09 12:49:40.124527','2018-04-09 12:49:40.124722','水费',113),(549,'2018-04-09 12:49:47.944100','2018-04-09 12:49:47.944139','电费',113),(550,'2018-04-09 12:49:55.874111','2018-04-09 12:49:55.874156','煤气费',113),(551,'2018-04-09 12:50:05.470708','2018-04-09 12:50:05.470749','城市通',113),(552,'2018-04-09 12:50:21.772953','2018-04-09 12:50:21.773025','家政保洁',114),(553,'2018-04-09 12:50:36.536493','2018-04-09 12:50:36.536542','摄影写真',114),(554,'2018-04-09 12:50:50.325220','2018-04-09 12:50:50.325264','养生',114),(555,'2018-04-09 12:51:01.075371','2019-01-28 08:54:01.187505','代理代办',114);
/*!40000 ALTER TABLE `tb_goods_category` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_goods_channel`
--

DROP TABLE IF EXISTS `tb_goods_channel`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_goods_channel` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `group_id` int(11) NOT NULL,
  `url` varchar(50) NOT NULL,
  `sequence` int(11) NOT NULL,
  `category_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_goods_channel_category_id_8e1b1d82_fk_tb_goods_category_id` (`category_id`),
  CONSTRAINT `tb_goods_channel_category_id_8e1b1d82_fk_tb_goods_category_id` FOREIGN KEY (`category_id`) REFERENCES `tb_goods_category` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=38 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_goods_channel`
--

LOCK TABLES `tb_goods_channel` WRITE;
/*!40000 ALTER TABLE `tb_goods_channel` DISABLE KEYS */;
INSERT INTO `tb_goods_channel` VALUES (1,'2018-04-09 09:15:38.057078','2018-04-09 09:15:38.057150',1,'http://shouji.jd.com',1,1),(2,'2018-04-09 09:17:29.097657','2018-04-09 09:17:29.097706',1,'http://www.itcast.cn',2,2),(3,'2018-04-09 09:17:45.065222','2018-04-09 09:17:45.065264',1,'http://www.itcast.cn',3,3),(4,'2018-04-09 09:18:10.865628','2018-04-09 09:18:10.865669',2,'http://www.itcast.cn',1,4),(5,'2018-04-09 09:18:26.508512','2018-04-09 09:18:26.508581',2,'http://www.itcast.cn',2,5),(6,'2018-04-09 09:18:44.054270','2018-04-09 09:18:44.054322',2,'http://www.itcast.cn',3,6),(7,'2018-04-09 09:19:17.539464','2018-04-09 09:19:17.539538',3,'http://www.itcast.cn',1,7),(8,'2018-04-09 09:19:27.460701','2018-04-09 09:19:27.460744',3,'http://www.itcast.cn',2,8),(9,'2018-04-09 09:19:40.863343','2018-04-09 09:19:40.863387',3,'http://www.itcast.cn',3,9),(10,'2018-04-09 09:19:50.561302','2018-04-09 09:19:50.561364',3,'http://www.itcast.cn',4,10),(11,'2018-04-09 09:20:01.493344','2018-04-09 09:20:01.493495',4,'http://www.itcast.cn',1,11),(12,'2018-04-09 09:20:34.086724','2018-04-09 09:20:34.086785',4,'http://www.itcast.cn',2,12),(13,'2018-04-09 09:20:42.379403','2018-04-09 09:20:42.379451',4,'http://www.itcast.cn',4,13),(14,'2018-04-09 09:21:28.958754','2018-04-09 09:21:28.958795',4,'http://www.itcast.cn',4,14),(15,'2018-04-09 09:21:40.106887','2018-04-09 09:21:40.106969',5,'http://www.itcast.cn',1,15),(16,'2018-04-09 09:21:53.353755','2018-04-09 09:21:53.353799',5,'http://www.itcast.cn',2,16),(17,'2018-04-09 09:22:00.609357','2018-04-09 09:22:00.609399',5,'http://www.itcast.cn',3,17),(18,'2018-04-09 09:22:22.954795','2018-04-09 09:22:22.954840',5,'http://www.itcast.cn',4,18),(19,'2018-04-09 09:22:36.104435','2018-04-09 09:22:36.104479',6,'http://www.itcast.cn',1,19),(20,'2018-04-09 09:22:45.332578','2018-04-09 09:22:45.332620',6,'http://www.itcast.cn',2,20),(21,'2018-04-09 09:22:54.175772','2018-04-09 09:22:54.176014',6,'http://www.itcast.cn',3,21),(22,'2018-04-09 09:23:05.485045','2018-04-09 09:23:05.485122',7,'http://www.itcast.cn',1,22),(23,'2018-04-09 09:23:15.810944','2018-04-09 09:23:15.810994',7,'http://www.itcast.cn',2,23),(24,'2018-04-09 09:23:23.689513','2018-04-09 09:23:23.689560',7,'http://www.itcast.cn',3,24),(25,'2018-04-09 09:23:35.724733','2018-04-09 09:23:35.724773',8,'http://www.itcast.cn',1,25),(26,'2018-04-09 09:23:48.261767','2018-04-09 09:23:48.261814',8,'http://www.itcast.cn',2,26),(27,'2018-04-09 09:24:03.645182','2018-04-09 09:24:03.645227',9,'http://www.itcast.cn',1,27),(28,'2018-04-09 09:24:23.379561','2018-04-09 09:24:23.379603',9,'http://www.itcast.cn',2,28),(29,'2018-04-09 09:24:35.402469','2018-04-09 09:24:35.402513',9,'http://www.itcast.cn',3,29),(30,'2018-04-09 09:24:52.890507','2018-04-09 09:24:52.890549',9,'http://www.itcast.cn',4,30),(31,'2018-04-09 09:25:00.005576','2018-04-09 09:25:00.005658',10,'http://www.itcast.cn',1,31),(32,'2018-04-09 09:25:06.989099','2018-04-09 09:25:06.989139',10,'http://www.itcast.cn',2,32),(33,'2018-04-09 09:25:13.785850','2018-04-09 09:25:13.785911',10,'http://www.itcast.cn',3,33),(34,'2018-04-09 09:25:21.231690','2018-04-09 09:25:21.231772',11,'http://www.itcast.cn',1,34),(35,'2018-04-09 09:25:30.766132','2018-04-09 09:25:30.766177',11,'http://www.itcast.cn',2,35),(36,'2018-04-09 09:25:43.574584','2018-04-09 09:25:43.574629',11,'http://www.itcast.cn',3,36),(37,'2018-04-09 09:26:00.332843','2018-04-26 13:13:00.959857',11,'http://www.itcast.cn',4,37);
/*!40000 ALTER TABLE `tb_goods_channel` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_goods_specification`
--

DROP TABLE IF EXISTS `tb_goods_specification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_goods_specification` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `name` varchar(20) NOT NULL,
  `goods_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_goods_specification_goods_id_41f4eda6_fk_tb_goods_id` (`goods_id`),
  CONSTRAINT `tb_goods_specification_goods_id_41f4eda6_fk_tb_goods_id` FOREIGN KEY (`goods_id`) REFERENCES `tb_goods` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_goods_specification`
--

LOCK TABLES `tb_goods_specification` WRITE;
/*!40000 ALTER TABLE `tb_goods_specification` DISABLE KEYS */;
INSERT INTO `tb_goods_specification` VALUES (1,'2018-04-11 17:20:30.142577','2018-04-11 17:20:30.142657','屏幕尺寸',1),(2,'2018-04-11 17:21:57.862419','2018-04-11 17:21:57.862464','颜色',1),(3,'2018-04-11 17:22:04.687913','2018-04-11 17:22:04.687956','版本',1),(4,'2018-04-14 02:10:32.810681','2018-04-14 02:10:32.810728','颜色',2),(5,'2018-04-14 02:10:39.748266','2018-04-14 02:10:39.748314','内存',2),(6,'2018-04-14 03:04:39.450373','2018-04-14 03:04:39.450418','颜色',3),(7,'2018-04-14 03:04:50.182073','2018-04-14 03:04:50.182118','版本',3);
/*!40000 ALTER TABLE `tb_goods_specification` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_order_goods`
--

DROP TABLE IF EXISTS `tb_order_goods`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_order_goods` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `count` int(11) NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `comment` longtext NOT NULL,
  `score` smallint(6) NOT NULL,
  `is_anonymous` tinyint(1) NOT NULL,
  `is_commented` tinyint(1) NOT NULL,
  `order_id` varchar(64) NOT NULL,
  `sku_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_order_goods_order_id_3cce2d8f_fk_tb_table_info_order_id` (`order_id`),
  KEY `tb_order_goods_sku_id_e335e3b1_fk_tb_sku_id` (`sku_id`),
  CONSTRAINT `tb_order_goods_order_id_3cce2d8f_fk_tb_table_info_order_id` FOREIGN KEY (`order_id`) REFERENCES `tb_order_info` (`order_id`),
  CONSTRAINT `tb_order_goods_sku_id_e335e3b1_fk_tb_sku_id` FOREIGN KEY (`sku_id`) REFERENCES `tb_sku` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=19 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_order_goods`
--

LOCK TABLES `tb_order_goods` WRITE;
/*!40000 ALTER TABLE `tb_order_goods` DISABLE KEYS */;
INSERT INTO `tb_order_goods` VALUES (1,'2019-02-17 08:41:30.979886','2019-02-17 08:41:30.979944',1,3788.00,'',5,0,0,'20190217084130000000001',16),(2,'2019-02-17 08:41:31.010658','2019-02-17 08:41:31.010714',1,11388.00,'',5,0,0,'20190217084130000000001',1),(3,'2019-02-17 11:20:23.895107','2019-02-17 11:20:23.895187',4,11388.00,'',5,0,0,'20190217112018000000001',1),(4,'2019-02-17 13:00:52.307191','2019-02-17 13:00:52.307233',2,3788.00,'',5,0,0,'20190217130047000000001',16),(5,'2019-02-17 14:00:04.075009','2019-02-17 14:00:04.075067',1,3788.00,'',5,0,0,'20190217135959000000001',16),(6,'2019-02-17 14:04:03.856035','2019-02-17 14:04:03.856084',1,3788.00,'',5,0,0,'20190217140358000000001',16),(7,'2019-02-17 14:08:31.559411','2019-02-17 14:08:31.559459',1,11388.00,'',5,0,0,'20190217140826000000001',1),(8,'2019-02-17 14:19:27.009462','2019-02-17 14:19:27.009515',1,11388.00,'',5,0,0,'20190217141921000000001',1),(9,'2019-02-18 12:34:31.511043','2019-02-18 12:34:31.511104',1,3388.00,'',5,0,0,'20190218123426000000001',15),(10,'2019-02-18 12:37:05.541462','2019-02-18 12:37:05.541513',1,11388.00,'',5,0,0,'20190218123705000000001',1),(11,'2019-02-23 03:59:03.393681','2019-02-23 03:59:03.393763',2,3788.00,'6666666666',1,1,1,'20190223035903000000008',16),(12,'2019-02-23 03:59:03.421419','2019-02-23 03:59:03.421568',1,11388.00,'88888888888',3,0,1,'20190223035903000000008',1),(13,'2019-02-23 04:06:44.427040','2019-02-23 04:06:44.427440',4,11398.00,'dddddddddddddd',3,0,1,'20190223040644000000008',2),(14,'2019-02-23 11:47:50.885412','2019-02-23 11:47:50.885582',2,11398.00,'77777777777777',2,0,1,'20190223114750000000011',2),(15,'2019-02-23 11:47:50.942653','2019-02-23 11:47:50.942816',3,3788.00,'77777777777777',4,0,1,'20190223114750000000011',14),(16,'2019-02-23 11:47:50.975657','2019-02-23 11:47:50.975818',2,3388.00,'777777777777777',4,0,1,'20190223114750000000011',15),(17,'2019-02-24 11:12:52.386801','2019-02-24 11:12:52.386877',1,3788.00,'7777777777777',3,0,1,'20190224111252000000011',16),(18,'2019-02-24 12:31:01.841283','2019-02-24 12:31:01.841416',1,3788.00,'77777777777',3,1,1,'20190224123101000000011',16);
/*!40000 ALTER TABLE `tb_order_goods` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_order_info`
--

DROP TABLE IF EXISTS `tb_order_info`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_order_info` (
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `order_id` varchar(64) NOT NULL,
  `total_count` int(11) NOT NULL,
  `total_amount` decimal(10,2) NOT NULL,
  `freight` decimal(10,2) NOT NULL,
  `pay_method` smallint(6) NOT NULL,
  `status` smallint(6) NOT NULL,
  `address_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`order_id`),
  KEY `tb_table_info_address_id_7daf747c_fk_tb_address_id` (`address_id`),
  KEY `tb_table_info_user_id_7fdd2d57_fk_tb_user_id` (`user_id`),
  CONSTRAINT `tb_table_info_address_id_7daf747c_fk_tb_address_id` FOREIGN KEY (`address_id`) REFERENCES `tb_address` (`id`),
  CONSTRAINT `tb_table_info_user_id_7fdd2d57_fk_tb_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_order_info`
--

LOCK TABLES `tb_order_info` WRITE;
/*!40000 ALTER TABLE `tb_order_info` DISABLE KEYS */;
INSERT INTO `tb_order_info` VALUES ('2019-02-17 08:41:30.928143','2019-02-17 08:41:31.018278','20190217084130000000001',3,15186.00,10.00,1,2,2,1),('2019-02-17 11:20:18.875388','2019-02-17 11:20:23.897285','20190217112018000000001',5,45562.00,10.00,1,2,2,1),('2019-02-17 13:00:47.294489','2019-02-17 13:00:52.308320','20190217130047000000001',3,7586.00,10.00,2,1,2,1),('2019-02-17 13:59:59.044685','2019-02-17 14:00:04.079737','20190217135959000000001',2,3798.00,10.00,2,1,2,1),('2019-02-17 14:03:58.839930','2019-02-17 14:04:03.857089','20190217140358000000001',2,3798.00,10.00,2,1,2,1),('2019-02-17 14:08:26.543530','2019-02-17 14:08:31.560778','20190217140826000000001',2,11398.00,10.00,2,2,2,1),('2019-02-17 14:19:21.995046','2019-02-17 14:19:27.010712','20190217141921000000001',2,11398.00,10.00,2,2,2,1),('2019-02-18 12:34:26.484321','2019-02-18 12:34:31.512756','20190218123426000000001',2,3398.00,10.00,1,2,2,1),('2019-02-18 12:37:05.521703','2019-02-18 12:37:05.543177','20190218123705000000001',2,11398.00,10.00,2,1,2,1),('2019-02-23 03:59:03.358822','2019-02-23 04:01:24.317053','20190223035903000000008',3,18974.00,10.00,2,5,4,8),('2019-02-23 04:06:44.321421','2019-02-23 04:07:15.165649','20190223040644000000008',4,45602.00,10.00,1,5,4,8),('2019-02-23 11:47:50.771482','2019-02-23 11:54:43.865150','20190223114750000000011',7,40946.00,10.00,1,5,5,11),('2019-02-24 11:12:52.335938','2019-02-24 12:33:42.735249','20190224111252000000011',1,3798.00,10.00,1,5,5,11),('2019-02-24 12:31:01.805324','2019-02-24 12:33:28.325803','20190224123101000000011',1,3798.00,10.00,2,5,5,11);
/*!40000 ALTER TABLE `tb_order_info` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_payment`
--

DROP TABLE IF EXISTS `tb_payment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_payment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `trade_id` varchar(100) DEFAULT NULL,
  `order_id` varchar(64) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `trade_id` (`trade_id`),
  KEY `tb_payment_order_id_e3bfc510_fk_tb_table_info_order_id` (`order_id`),
  CONSTRAINT `tb_payment_order_id_e3bfc510_fk_tb_table_info_order_id` FOREIGN KEY (`order_id`) REFERENCES `tb_order_info` (`order_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_payment`
--

LOCK TABLES `tb_payment` WRITE;
/*!40000 ALTER TABLE `tb_payment` DISABLE KEYS */;
INSERT INTO `tb_payment` VALUES (1,'2019-02-17 14:09:09.838057','2019-02-17 14:09:09.838670','2019021722001479810200997508','20190217140826000000001'),(2,'2019-02-17 14:20:53.717034','2019-02-17 14:20:53.717597','2019021722001479810200996818','20190217141921000000001'),(3,'2019-02-23 04:00:37.835410','2019-02-23 04:00:37.837572','2019022322001432460502755908','20190223035903000000008'),(4,'2019-02-24 12:32:13.952099','2019-02-24 12:32:13.953287','2019022422001432460502756685','20190224123101000000011');
/*!40000 ALTER TABLE `tb_payment` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_sina_auth`
--

DROP TABLE IF EXISTS `tb_sina_auth`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_sina_auth` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `access_token` varchar(64) NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_sina_auth_access_token_6c8296ec` (`access_token`),
  KEY `tb_sina_auth_user_id_fefed455_fk_tb_users_id` (`user_id`),
  CONSTRAINT `tb_sina_auth_user_id_fefed455_fk_tb_users_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=8 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_sina_auth`
--

LOCK TABLES `tb_sina_auth` WRITE;
/*!40000 ALTER TABLE `tb_sina_auth` DISABLE KEYS */;
INSERT INTO `tb_sina_auth` VALUES (6,'2019-02-24 13:35:12.149350','2019-02-24 13:35:12.149454','2.00bdxS5HJcPibD875df61da4zJrQZB',16),(7,'2019-02-24 14:07:17.968715','2019-02-24 14:07:17.968952','2.00WbqJeHJcPibDcd39d9c967vutpDE',17);
/*!40000 ALTER TABLE `tb_sina_auth` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_sku`
--

DROP TABLE IF EXISTS `tb_sku`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_sku` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `name` varchar(50) NOT NULL,
  `caption` varchar(100) NOT NULL,
  `price` decimal(10,2) NOT NULL,
  `cost_price` decimal(10,2) NOT NULL,
  `market_price` decimal(10,2) NOT NULL,
  `stock` int(11) NOT NULL,
  `sales` int(11) NOT NULL,
  `comments` int(11) NOT NULL,
  `is_launched` tinyint(1) NOT NULL,
  `category_id` int(11) NOT NULL,
  `goods_id` int(11) NOT NULL,
  `default_image_url` varchar(200) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_sku_category_id_23dd76b7_fk_tb_goods_category_id` (`category_id`),
  KEY `tb_sku_goods_id_fa5267c2_fk_tb_goods_id` (`goods_id`),
  CONSTRAINT `tb_sku_category_id_23dd76b7_fk_tb_goods_category_id` FOREIGN KEY (`category_id`) REFERENCES `tb_goods_category` (`id`),
  CONSTRAINT `tb_sku_goods_id_fa5267c2_fk_tb_goods_id` FOREIGN KEY (`goods_id`) REFERENCES `tb_goods` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=17 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_sku`
--

LOCK TABLES `tb_sku` WRITE;
/*!40000 ALTER TABLE `tb_sku` DISABLE KEYS */;
INSERT INTO `tb_sku` VALUES (1,'2018-04-11 17:28:21.804713','2019-02-23 04:01:21.034739','Apple MacBook Pro 13.3英寸笔记本 银色','【全新2017款】MacBook Pro,一身才华，一触，即发 了解【黑五返场特惠】 更多产品请点击【美多官方Apple旗舰店】',11388.00,10350.00,13388.00,8,14,2,1,157,1,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrPB4GAWkTlAAGuN6wB9fU4220429'),(2,'2018-04-12 06:53:54.575306','2019-02-23 11:54:43.915024','Apple MacBook Pro 13.3英寸笔记本 深灰色','【全新2017款】MacBook Pro,一身才华，一触，即发 了解【黑五返场特惠】 更多产品请点击【美多官方Apple旗舰店】',11398.00,10388.00,13398.00,3,7,2,1,157,1,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrPCAOAIKRBAAGvaeRBMfc0463515'),(3,'2018-04-14 02:14:04.599169','2018-04-14 17:26:54.041015','Apple iPhone 8 Plus (A1864) 64GB 金色 移动联通电信4G手机','选【移动优惠购】新机配新卡，198优质靓号，流量不限量！',6499.00,6300.00,6598.00,9,0,0,1,115,2,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRZCqAUxp9AAFti6upbx41220032'),(4,'2018-04-14 02:20:33.355996','2018-04-14 17:27:12.736139','Apple iPhone 8 Plus (A1864) 256GB 金色 移动联通电信4G手机','选【移动优惠购】新机配新卡，198优质靓号，流量不限量！',7988.00,7888.00,8088.00,9,2,0,1,115,2,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRZa6ANO_sAAFti6upbx40753757'),(5,'2018-04-14 02:45:23.341909','2018-04-14 17:27:17.181609','Apple iPhone 8 Plus (A1864) 64GB 深空灰色 移动联通电信4G手机','选【移动优惠购】新机配新卡，198优质靓号，流量不限量！',6688.00,6588.00,6788.00,9,0,0,1,115,2,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRa8iAZdz1AAFZsBqChgk2188464'),(6,'2018-04-14 02:49:40.912682','2018-04-25 11:09:35.936530','Apple iPhone 8 Plus (A1864) 256GB 深空灰色 移动联通电信4G手机','选【移动优惠购】新机配新卡，198优质靓号，流量不限量！',7988.00,7888.00,7988.00,9,5,1,1,115,2,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRbI2ARekNAAFZsBqChgk3141998'),(7,'2018-04-14 02:55:11.172604','2018-04-14 17:27:28.772353','Apple iPhone 8 Plus (A1864) 64GB 银色 移动联通电信4G手机','选【移动优惠购】新机配新卡，198优质靓号，流量不限量！',6688.00,6588.00,6788.00,9,0,0,1,115,2,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRbh2AX3JVAAFvJD02RWs4638828'),(8,'2018-04-14 02:56:17.331169','2019-02-12 03:56:00.644668','Apple iPhone 8 Plus (A1864) 256GB 银色 移动联通电信4G手机','选【移动优惠购】新机配新卡，198优质靓号，流量不限量！',7988.00,7888.00,7988.00,9,1,0,1,115,2,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRbjSAazeSAAFvJD02RWs2636429'),(9,'2018-04-14 03:09:00.909709','2018-04-14 17:27:40.624770','华为 HUAWEI P10 Plus 6GB+64GB 钻雕金 移动联通电信4G手机 双卡双待','wifi双天线设计！徕卡人像摄影！P10徕卡双摄拍照，低至2988元！',3388.00,3288.00,3388.00,9,0,0,1,115,3,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRcUeAHp9pAARfIK95am88523545'),(10,'2018-04-14 03:13:40.226704','2018-04-25 11:06:55.087206','华为 HUAWEI P10 Plus 6GB+128GB 钻雕金 移动联通电信4G手机 双卡双待','wifi双天线设计！徕卡人像摄影！P10徕卡双摄拍照，低至2988元！',3788.00,3588.00,3888.00,9,0,5,1,115,3,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRchWAMc8rAARfIK95am88158618'),(11,'2018-04-14 03:16:27.620102','2018-04-25 10:56:51.267674','华为 HUAWEI P10 Plus 6GB+128GB 钻雕蓝 移动联通电信4G手机 双卡双待','wifi双天线设计！徕卡人像摄影！P10徕卡双摄拍照，低至2988元！',3788.00,3588.00,3888.00,9,0,2,1,115,3,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRdG6AYdapAAcPaeOqMpA1594598'),(12,'2018-04-14 03:17:25.671905','2018-04-14 17:28:06.649098','华为 HUAWEI P10 Plus 6GB+64GB 钻雕蓝 移动联通电信4G手机 双卡双待','wifi双天线设计！徕卡人像摄影！P10徕卡双摄拍照，低至2988元！',3388.00,3288.00,3488.00,9,0,0,1,115,3,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRdICAO_CRAAcPaeOqMpA2024091'),(13,'2018-04-14 03:18:04.588296','2018-04-14 17:28:23.886231','华为 HUAWEI P10 Plus 6GB+64GB 玫瑰金 移动联通电信4G手机 双卡双待','wifi双天线设计！徕卡人像摄影！P10徕卡双摄拍照，低至2988元！',3388.00,3288.00,3488.00,9,0,0,1,115,3,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRdLGARgBAAAVslh9vkK00474545'),(14,'2018-04-14 03:19:03.691772','2019-02-23 11:54:31.812473','华为 HUAWEI P10 Plus 6GB+128GB 玫瑰金 移动联通电信4G手机 双卡双待','wifi双天线设计！徕卡人像摄影！P10徕卡双摄拍照，低至2988元！',3788.00,3588.00,3888.00,6,7,2,1,115,3,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRdMSAaDUtAAVslh9vkK04466364'),(15,'2018-04-14 03:20:00.777150','2019-02-23 11:54:39.296420','华为 HUAWEI P10 Plus 6GB+64GB 曜石黑 移动联通电信4G手机 双卡双待','wifi双天线设计！徕卡人像摄影！P10徕卡双摄拍照，低至2988元！',3388.00,3288.00,3488.00,7,5,1,1,115,3,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRdOiAUBFXAAYJrpessGQ2842711'),(16,'2018-04-14 03:20:36.855901','2019-02-24 12:33:42.761723','华为 HUAWEI P10 Plus 6GB+128GB 曜石黑 移动联通电信4G手机 双卡双待','666 wifi双天线设计！徕卡人像摄影！P10徕卡双摄拍照，低至2988元！',3788.00,3588.00,3888.00,5,9,3,1,115,3,'http://image.meiduo.site:8888/group1/M00/00/02/CtM3BVrRdPeAXNDMAAYJrpessGQ9777651');
/*!40000 ALTER TABLE `tb_sku` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_sku_image`
--

DROP TABLE IF EXISTS `tb_sku_image`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_sku_image` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `image` varchar(100) NOT NULL,
  `sku_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_sku_image_sku_id_8c6d7195_fk_tb_sku_id` (`sku_id`),
  CONSTRAINT `tb_sku_image_sku_id_8c6d7195_fk_tb_sku_id` FOREIGN KEY (`sku_id`) REFERENCES `tb_sku` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=44 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_sku_image`
--

LOCK TABLES `tb_sku_image` WRITE;
/*!40000 ALTER TABLE `tb_sku_image` DISABLE KEYS */;
INSERT INTO `tb_sku_image` VALUES (4,'2018-04-12 07:15:13.873180','2018-04-14 17:26:14.513939','group1/M00/00/02/CtM3BVrPB4GAWkTlAAGuN6wB9fU4220429',1),(5,'2018-04-12 07:15:21.029143','2018-04-12 07:15:21.029186','group1/M00/00/02/CtM3BVrPB4mAEq_WAADhmMQLkZM2624277',1),(6,'2018-04-12 07:15:28.362779','2018-04-12 07:15:28.362824','group1/M00/00/02/CtM3BVrPB5CALKn6AADq-Afr0eE1672090',1),(7,'2018-04-12 07:17:23.935313','2018-04-14 17:26:49.549376','group1/M00/00/02/CtM3BVrPCAOAIKRBAAGvaeRBMfc0463515',2),(8,'2018-04-12 07:17:31.408278','2018-04-12 07:17:31.408320','group1/M00/00/02/CtM3BVrPCAuAYqIcAAD_zetbIJ84926354',2),(9,'2018-04-12 07:17:39.201787','2018-04-12 07:17:39.201830','group1/M00/00/02/CtM3BVrPCBOADuuvAADq-Afr0eE9666965',2),(10,'2018-04-14 02:15:06.992811','2018-04-14 17:26:54.035453','group1/M00/00/02/CtM3BVrRZCqAUxp9AAFti6upbx41220032',3),(11,'2018-04-14 02:15:14.933468','2018-04-14 02:15:14.933510','group1/M00/00/02/CtM3BVrRZDKAXCsoAANy-gDBsak1396581',3),(12,'2018-04-14 02:15:23.533360','2018-04-14 02:15:23.533402','group1/M00/00/02/CtM3BVrRZDuAHu9qAAEoJ7X2Zrk9446545',3),(13,'2018-04-14 02:21:34.330147','2018-04-14 17:27:12.729883','group1/M00/00/02/CtM3BVrRZa6ANO_sAAFti6upbx40753757',4),(14,'2018-04-14 02:21:42.216194','2018-04-14 02:21:42.216237','group1/M00/00/02/CtM3BVrRZbaATwU2AANy-gDBsak6195744',4),(15,'2018-04-14 02:21:50.087699','2018-04-14 02:21:50.087747','group1/M00/00/02/CtM3BVrRZb6Ac6FFAAEoJ7X2Zrk5720374',4),(16,'2018-04-14 02:47:36.030339','2018-04-14 17:27:17.174392','group1/M00/00/02/CtM3BVrRa8iAZdz1AAFZsBqChgk2188464',5),(17,'2018-04-14 02:47:44.351127','2018-04-14 02:47:44.351183','group1/M00/00/02/CtM3BVrRa9CARC7lAAMO0cff_1g7347921',5),(18,'2018-04-14 02:47:54.952219','2018-04-14 02:47:54.952277','group1/M00/00/02/CtM3BVrRa9qAbCXWAAEovaKouDU2764892',5),(19,'2018-04-14 02:50:53.037181','2018-04-14 17:27:23.920025','group1/M00/00/02/CtM3BVrRbI2ARekNAAFZsBqChgk3141998',6),(20,'2018-04-14 02:51:01.518195','2018-04-14 02:51:01.518241','group1/M00/00/02/CtM3BVrRbJWAEllkAAMO0cff_1g6980672',6),(21,'2018-04-14 02:51:11.648093','2018-04-14 02:51:11.648139','group1/M00/00/02/CtM3BVrRbJ-AIjVcAAEovaKouDU7324803',6),(22,'2018-04-14 02:57:33.556398','2018-04-14 17:27:28.765339','group1/M00/00/02/CtM3BVrRbh2AX3JVAAFvJD02RWs4638828',7),(23,'2018-04-14 02:57:41.405287','2018-04-14 02:57:41.405329','group1/M00/00/02/CtM3BVrRbiWAYvb5AAM7qusgQKA1299367',7),(24,'2018-04-14 02:57:49.310718','2018-04-14 02:57:49.310778','group1/M00/00/02/CtM3BVrRbi2AIt2gAAEtG6xmEQk0223613',7),(25,'2018-04-14 02:57:56.642831','2018-04-14 17:27:34.529926','group1/M00/00/02/CtM3BVrRbjSAazeSAAFvJD02RWs2636429',8),(26,'2018-04-14 02:58:04.268608','2018-04-14 02:58:04.268654','group1/M00/00/02/CtM3BVrRbjyAQQWfAAM7qusgQKA3083019',8),(27,'2018-04-14 02:58:15.478936','2018-04-14 02:58:15.478988','group1/M00/00/02/CtM3BVrRbkeAOtIYAAEtG6xmEQk7850211',8),(28,'2018-04-14 03:11:03.449568','2018-04-14 17:27:40.618166','group1/M00/00/02/CtM3BVrRcUeAHp9pAARfIK95am88523545',9),(29,'2018-04-14 03:11:12.819881','2018-04-14 03:11:12.819935','group1/M00/00/02/CtM3BVrRcVCASV6vAALt1TiUHbQ0320035',9),(30,'2018-04-14 03:14:29.035188','2018-04-14 17:27:54.908811','group1/M00/00/02/CtM3BVrRchWAMc8rAARfIK95am88158618',10),(31,'2018-04-14 03:14:38.491138','2018-04-14 03:14:38.491185','group1/M00/00/02/CtM3BVrRch6AO_L1AALt1TiUHbQ6329774',10),(32,'2018-04-14 03:24:30.185682','2018-04-14 17:28:01.108758','group1/M00/00/02/CtM3BVrRdG6AYdapAAcPaeOqMpA1594598',11),(33,'2018-04-14 03:24:38.335784','2018-04-14 03:24:38.335829','group1/M00/00/02/CtM3BVrRdHaAO6nxAARV14yhum85841702',11),(34,'2018-04-14 03:24:48.608311','2018-04-14 17:28:38.713367','group1/M00/00/02/CtM3BVrRdICAO_CRAAcPaeOqMpA2024091',12),(35,'2018-04-14 03:25:03.588442','2018-04-14 03:25:03.588487','group1/M00/00/02/CtM3BVrRdI-ACDCRAARV14yhum80519978',12),(36,'2018-04-14 03:25:38.029709','2018-04-14 17:28:23.878317','group1/M00/00/02/CtM3BVrRdLGARgBAAAVslh9vkK00474545',13),(37,'2018-04-14 03:25:46.628907','2018-04-14 03:25:46.628954','group1/M00/00/02/CtM3BVrRdLqAD5leAAMdyS99nTA6298698',13),(38,'2018-04-14 03:25:56.073002','2018-04-14 17:28:20.655513','group1/M00/00/02/CtM3BVrRdMSAaDUtAAVslh9vkK04466364',14),(39,'2018-04-14 03:26:04.263619','2018-04-14 03:26:04.263668','group1/M00/00/02/CtM3BVrRdMyAPoryAAMdyS99nTA1388842',14),(40,'2018-04-14 03:26:32.774444','2018-04-14 17:28:16.733407','group1/M00/00/02/CtM3BVrRdOiAUBFXAAYJrpessGQ2842711',15),(41,'2018-04-14 03:26:40.033032','2018-04-14 03:26:40.033091','group1/M00/00/02/CtM3BVrRdPCAed9FAAQ3kdJbqeQ7404140',15),(42,'2018-04-14 03:26:47.275669','2018-04-14 17:28:13.652820','group1/M00/00/02/CtM3BVrRdPeAXNDMAAYJrpessGQ9777651',16),(43,'2018-04-14 03:27:00.359589','2018-04-14 03:27:00.359636','group1/M00/00/02/CtM3BVrRdQSAHxqbAAQ3kdJbqeQ1136308',16);
/*!40000 ALTER TABLE `tb_sku_image` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_sku_specification`
--

DROP TABLE IF EXISTS `tb_sku_specification`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_sku_specification` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `option_id` int(11) NOT NULL,
  `sku_id` int(11) NOT NULL,
  `spec_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_sku_specification_option_id_80a17a3d_fk_tb_specif` (`option_id`),
  KEY `tb_sku_specification_sku_id_10aee5ae_fk_tb_sku_id` (`sku_id`),
  KEY `tb_sku_specification_spec_id_5aa6db0c_fk_tb_goods_` (`spec_id`),
  CONSTRAINT `tb_sku_specification_option_id_80a17a3d_fk_tb_specif` FOREIGN KEY (`option_id`) REFERENCES `tb_specification_option` (`id`),
  CONSTRAINT `tb_sku_specification_sku_id_10aee5ae_fk_tb_sku_id` FOREIGN KEY (`sku_id`) REFERENCES `tb_sku` (`id`),
  CONSTRAINT `tb_sku_specification_spec_id_5aa6db0c_fk_tb_goods_` FOREIGN KEY (`spec_id`) REFERENCES `tb_goods_specification` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=35 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_sku_specification`
--

LOCK TABLES `tb_sku_specification` WRITE;
/*!40000 ALTER TABLE `tb_sku_specification` DISABLE KEYS */;
INSERT INTO `tb_sku_specification` VALUES (1,'2018-04-11 17:53:37.178101','2018-04-11 17:53:37.178148',1,1,1),(2,'2018-04-11 17:56:00.141036','2018-04-11 17:56:00.141078',4,1,2),(3,'2018-04-11 17:56:17.907973','2018-04-11 17:56:17.908017',7,1,3),(4,'2018-04-12 07:11:20.138634','2018-04-12 07:11:20.138677',1,2,1),(5,'2018-04-12 07:11:28.227056','2018-04-12 07:11:28.227099',3,2,2),(6,'2018-04-12 07:11:48.046789','2018-04-12 07:11:48.046885',7,2,3),(7,'2018-04-14 02:16:36.204410','2018-04-14 02:16:36.204453',8,3,4),(8,'2018-04-14 02:16:44.309888','2018-04-14 02:16:44.309972',11,3,5),(9,'2018-04-14 02:20:55.765324','2018-04-14 02:20:55.765377',8,4,4),(10,'2018-04-14 02:21:04.971106','2018-04-14 02:21:04.971155',12,4,5),(11,'2018-04-14 02:45:41.913322','2018-04-14 02:45:41.913372',9,5,4),(12,'2018-04-14 02:45:50.801926','2018-04-14 02:45:50.802005',11,5,5),(13,'2018-04-14 02:50:00.232648','2018-04-14 02:50:00.232694',9,6,4),(14,'2018-04-14 02:50:08.715882','2018-04-14 02:50:08.715927',12,6,5),(15,'2018-04-14 02:56:48.320934','2018-04-14 02:56:48.320980',10,7,4),(16,'2018-04-14 02:56:55.879794','2018-04-14 02:56:55.879839',11,7,5),(17,'2018-04-14 02:57:04.305406','2018-04-14 02:57:04.305462',10,8,4),(18,'2018-04-14 02:57:12.212999','2018-04-14 02:57:12.213047',12,8,5),(19,'2018-04-14 03:10:09.203601','2018-04-14 03:10:09.203646',13,9,6),(20,'2018-04-14 03:10:19.242994','2018-04-14 03:10:19.243421',20,9,7),(21,'2018-04-14 03:14:02.319574','2018-04-14 03:14:02.319621',13,10,6),(22,'2018-04-14 03:14:14.554189','2018-04-14 03:14:14.554237',21,10,7),(23,'2018-04-14 03:21:25.602470','2018-04-14 03:21:25.602519',14,11,6),(24,'2018-04-14 03:21:38.123239','2018-04-14 03:21:38.123285',21,11,7),(25,'2018-04-14 03:21:48.843531','2018-04-14 03:21:48.843577',14,12,6),(26,'2018-04-14 03:22:01.324252','2018-04-14 03:22:01.324321',20,12,7),(27,'2018-04-14 03:22:11.921568','2018-04-14 03:22:11.921613',15,13,6),(28,'2018-04-14 03:22:23.702276','2018-04-14 03:22:23.702323',20,13,7),(29,'2018-04-14 03:22:45.382268','2018-04-14 03:22:45.382313',15,14,6),(30,'2018-04-14 03:22:53.418091','2018-04-14 03:22:53.418147',21,14,7),(31,'2018-04-14 03:23:02.508118','2018-04-14 03:23:02.508186',16,15,6),(32,'2018-04-14 03:23:12.294204','2018-04-14 03:23:12.294255',20,15,7),(33,'2018-04-14 03:23:20.134049','2018-04-14 03:23:20.134095',16,16,6),(34,'2018-04-14 03:23:36.250798','2018-04-14 03:23:36.250844',21,16,7);
/*!40000 ALTER TABLE `tb_sku_specification` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_specification_option`
--

DROP TABLE IF EXISTS `tb_specification_option`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_specification_option` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `create_time` datetime(6) NOT NULL,
  `update_time` datetime(6) NOT NULL,
  `value` varchar(20) NOT NULL,
  `spec_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `tb_specification_opt_spec_id_3f11adee_fk_tb_goods_` (`spec_id`),
  CONSTRAINT `tb_specification_opt_spec_id_3f11adee_fk_tb_goods_` FOREIGN KEY (`spec_id`) REFERENCES `tb_goods_specification` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=22 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_specification_option`
--

LOCK TABLES `tb_specification_option` WRITE;
/*!40000 ALTER TABLE `tb_specification_option` DISABLE KEYS */;
INSERT INTO `tb_specification_option` VALUES (1,'2018-04-11 17:22:55.126053','2018-04-11 17:22:55.126095','13.3英寸',1),(2,'2018-04-11 17:24:04.841221','2018-04-11 17:24:04.841265','15.4英寸',1),(3,'2018-04-11 17:24:23.862341','2018-04-11 17:24:23.862385','深灰色',2),(4,'2018-04-11 17:24:35.256820','2018-04-11 17:24:35.256868','银色',2),(5,'2018-04-11 17:25:04.607535','2018-04-11 17:25:04.607604','core i5/8G内存/256G存储',3),(6,'2018-04-11 17:25:15.969671','2018-04-11 17:25:15.969714','core i5/8G内存/128G存储',3),(7,'2018-04-11 17:25:35.025857','2018-04-12 07:12:08.090494','core i5/8G内存/512G存储',3),(8,'2018-04-14 02:11:12.231649','2018-04-14 02:11:12.231700','金色',4),(9,'2018-04-14 02:11:21.073811','2018-04-14 02:11:21.073917','深空灰',4),(10,'2018-04-14 02:11:27.692284','2018-04-14 02:11:27.692329','银色',4),(11,'2018-04-14 02:11:35.967113','2018-04-14 02:11:35.967163','64GB',5),(12,'2018-04-14 02:11:42.557263','2018-04-14 02:11:42.557354','256GB',5),(13,'2018-04-14 03:05:48.316724','2018-04-14 03:05:48.316835','钻雕金',6),(14,'2018-04-14 03:05:58.478640','2018-04-14 03:05:58.478689','钻雕蓝',6),(15,'2018-04-14 03:06:05.995609','2018-04-14 03:06:05.995652','玫瑰金',6),(16,'2018-04-14 03:06:37.587555','2018-04-14 03:06:37.587603','曜石黑',6),(20,'2018-04-14 03:07:15.727628','2018-04-14 03:07:15.727670','64GB',7),(21,'2018-04-14 03:07:23.480154','2018-04-14 03:07:23.480237','128GB',7);
/*!40000 ALTER TABLE `tb_specification_option` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_user_groups`
--

DROP TABLE IF EXISTS `tb_user_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_user_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tb_user_groups_user_id_group_id_adb62351_uniq` (`user_id`,`group_id`),
  KEY `tb_user_groups_group_id_3d826fde_fk_auth_group_id` (`group_id`),
  CONSTRAINT `tb_user_groups_group_id_3d826fde_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  CONSTRAINT `tb_user_groups_user_id_162ae03c_fk_tb_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_user_groups`
--

LOCK TABLES `tb_user_groups` WRITE;
/*!40000 ALTER TABLE `tb_user_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `tb_user_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_user_user_permissions`
--

DROP TABLE IF EXISTS `tb_user_user_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_user_user_permissions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tb_user_user_permissions_user_id_permission_id_fb1d58db_uniq` (`user_id`,`permission_id`),
  KEY `tb_user_user_permiss_permission_id_83890c0b_fk_auth_perm` (`permission_id`),
  CONSTRAINT `tb_user_user_permiss_permission_id_83890c0b_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `tb_user_user_permissions_user_id_1b639637_fk_tb_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_user_user_permissions`
--

LOCK TABLES `tb_user_user_permissions` WRITE;
/*!40000 ALTER TABLE `tb_user_user_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `tb_user_user_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_users`
--

DROP TABLE IF EXISTS `tb_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `password` varchar(128) NOT NULL,
  `last_login` datetime(6) DEFAULT NULL,
  `is_superuser` tinyint(1) NOT NULL,
  `username` varchar(150) NOT NULL,
  `first_name` varchar(30) NOT NULL,
  `last_name` varchar(30) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_staff` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `date_joined` datetime(6) NOT NULL,
  `mobile` varchar(11) NOT NULL,
  `email_active` tinyint(1) NOT NULL,
  `default_address_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `mobile` (`mobile`),
  KEY `tb_user_default_address_id_2ae8190b_fk_tb_address_id` (`default_address_id`),
  CONSTRAINT `tb_user_default_address_id_2ae8190b_fk_tb_address_id` FOREIGN KEY (`default_address_id`) REFERENCES `tb_address` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=18 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_users`
--

LOCK TABLES `tb_users` WRITE;
/*!40000 ALTER TABLE `tb_users` DISABLE KEYS */;
INSERT INTO `tb_users` VALUES (1,'pbkdf2_sha256$36000$h3ZxIqUI7JrM$MydWq6WlTetqF9nlyhCnSPTFdMzpPQCHZTLaLBJbKx4=',NULL,0,'qaz1234','','','2335223348@qq.com',0,1,'2019-01-20 08:22:45.934371','13434792337',1,2),(2,'pbkdf2_sha256$36000$EupVFghDj9aN$KzKJe7rhFYV4tgoacIfM5YfAxDKUIAzF3QU6FiiQqEc=',NULL,0,'qaz12345','','','',0,1,'2019-01-21 11:34:02.066753','13434792338',0,3),(3,'pbkdf2_sha256$36000$E9S7cy7AjCXB$6BP52dz+6tn4DnxJsidz8DN6FCAXU4/vGK69446/jZA=',NULL,0,'qaz1235','','','',0,1,'2019-01-21 12:07:21.016177','13434792339',0,NULL),(4,'pbkdf2_sha256$36000$2jyCDc6saf08$V6bNiconzWpJuXjk3E2KC8gZ6Plwyq93LYGUa4vV54s=',NULL,0,'qaz1236','','','',0,1,'2019-01-21 12:10:51.811557','13434792331',0,NULL),(5,'pbkdf2_sha256$36000$43cUP2Jp16GP$yfTRKdwof8dZ1YYu1UYZw3EFlBV/OFlYia0YRpr5mrI=',NULL,0,'SSS','','','',0,1,'2019-01-23 02:24:10.178527','13434792336',0,NULL),(6,'pbkdf2_sha256$36000$zoj3BZyUG38J$0IJGLpE00My//Vf5H1SFquUYCNLG1I2u6CpwZ9exN+0=',NULL,0,'DDD','','','',0,1,'2019-01-23 02:30:50.949927','13434792330',0,NULL),(7,'pbkdf2_sha256$36000$cae2FFOiOttC$BDD10FzIRdUGx+5bfb/eYRetxO+tWL5ZoUfb3wTG7RQ=','2019-02-12 01:24:16.621247',1,'admin','','','123@qq.com',1,1,'2019-01-27 12:17:49.572335','',0,NULL),(8,'pbkdf2_sha256$36000$RggueC99bnNv$g8NXbE4XaQ3DY1R4sd2r8g4qiNm8iO8ogFrVd/cGX30=',NULL,0,'ddas','','','',0,1,'2019-02-23 03:46:52.372010','18699372607',0,4),(9,'pbkdf2_sha256$36000$QtdUknqHBaS2$C9ObRXPpGOjhFy+WmK+TSxfOdNGx7DjJC89hTMXWqoI=',NULL,0,'sdf','','','',0,1,'2019-02-23 07:21:45.202006','18696372969',0,NULL),(11,'pbkdf2_sha256$36000$dW8B6XwQNOsA$tsrqHv8s5LE+8JcbZMLfkPI0iCK64ipGRwDKMZ5g6CU=',NULL,0,'dfdd','','','',0,1,'2019-02-23 08:43:22.530636','18697372967',0,5),(12,'pbkdf2_sha256$36000$WnKDhAC9c1lw$EUTheCjhlPGIB310olrbodp5Iass2tUp4HsP+M0VIcI=',NULL,0,'fty90372667','','','',0,1,'2019-02-24 12:42:32.584861','18696372367',0,NULL),(13,'pbkdf2_sha256$36000$g1i3xChyhGhQ$mnpiN74wLOyr+sKSS74WJRtRx+j4rcrRZ/VHXaZi3m8=',NULL,0,'17718853128','','','',0,1,'2019-02-24 12:48:11.813860','17718853128',0,NULL),(14,'pbkdf2_sha256$36000$qxpS41D5clUt$YBbS8CN5WapLRvqYg6NPJvHVsc7TpT7kGxZLY9SDg9A=',NULL,0,'18699372667','','','',0,1,'2019-02-24 12:55:17.847359','18690372667',0,NULL),(15,'pbkdf2_sha256$36000$ccHIqHO3e4YF$BSvL5xc6stLrqezCOO7uPdoQL6nDBiiJFSwlcxGvypE=',NULL,0,'17718859128','','','',0,1,'2019-02-24 13:02:08.769594','17718859128',0,NULL),(16,'pbkdf2_sha256$36000$eXIlCCAf1Fox$DjgNRmF+tt++1Y1LyXxT6SV70efvLkTCkBAIrKy+ksk=',NULL,0,'17718853129','','','',0,1,'2019-02-24 13:35:11.932598','17718853129',0,NULL),(17,'pbkdf2_sha256$36000$61ZkJoQUlCls$a7CzxrB8YyiYwLbY5CfYuF29r80qg6ONJf7E2GJI0nE=',NULL,0,'A17676767666','','','',0,1,'2019-02-24 14:07:17.811722','18696372667',0,NULL);
/*!40000 ALTER TABLE `tb_users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_users_groups`
--

DROP TABLE IF EXISTS `tb_users_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_users_groups` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tb_users_groups_user_id_group_id_5a177a84_uniq` (`user_id`,`group_id`),
  KEY `tb_users_groups_group_id_04d64563_fk_auth_group_id` (`group_id`),
  CONSTRAINT `tb_users_groups_group_id_04d64563_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  CONSTRAINT `tb_users_groups_user_id_5f9e3ed0_fk_tb_users_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_users_groups`
--

LOCK TABLES `tb_users_groups` WRITE;
/*!40000 ALTER TABLE `tb_users_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `tb_users_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tb_users_user_permissions`
--

DROP TABLE IF EXISTS `tb_users_user_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tb_users_user_permissions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tb_users_user_permissions_user_id_permission_id_064c2ef6_uniq` (`user_id`,`permission_id`),
  KEY `tb_users_user_permis_permission_id_b9b3ac94_fk_auth_perm` (`permission_id`),
  CONSTRAINT `tb_users_user_permis_permission_id_b9b3ac94_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `tb_users_user_permissions_user_id_2726c819_fk_tb_users_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tb_users_user_permissions`
--

LOCK TABLES `tb_users_user_permissions` WRITE;
/*!40000 ALTER TABLE `tb_users_user_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `tb_users_user_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `xadmin_bookmark`
--

DROP TABLE IF EXISTS `xadmin_bookmark`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `xadmin_bookmark` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(128) NOT NULL,
  `url_name` varchar(64) NOT NULL,
  `query` varchar(1000) NOT NULL,
  `is_share` tinyint(1) NOT NULL,
  `content_type_id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `xadmin_bookmark_content_type_id_60941679_fk_django_co` (`content_type_id`),
  KEY `xadmin_bookmark_user_id_42d307fc_fk_tb_user_id` (`user_id`),
  CONSTRAINT `xadmin_bookmark_content_type_id_60941679_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `xadmin_bookmark_user_id_42d307fc_fk_tb_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `xadmin_bookmark`
--

LOCK TABLES `xadmin_bookmark` WRITE;
/*!40000 ALTER TABLE `xadmin_bookmark` DISABLE KEYS */;
/*!40000 ALTER TABLE `xadmin_bookmark` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `xadmin_log`
--

DROP TABLE IF EXISTS `xadmin_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `xadmin_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `action_time` datetime(6) NOT NULL,
  `ip_addr` char(39) DEFAULT NULL,
  `object_id` longtext,
  `object_repr` varchar(200) NOT NULL,
  `action_flag` varchar(32) NOT NULL,
  `message` longtext NOT NULL,
  `content_type_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `xadmin_log_content_type_id_2a6cb852_fk_django_content_type_id` (`content_type_id`),
  KEY `xadmin_log_user_id_bb16a176_fk_tb_user_id` (`user_id`),
  CONSTRAINT `xadmin_log_content_type_id_2a6cb852_fk_django_content_type_id` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `xadmin_log_user_id_bb16a176_fk_tb_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `xadmin_log`
--

LOCK TABLES `xadmin_log` WRITE;
/*!40000 ALTER TABLE `xadmin_log` DISABLE KEYS */;
INSERT INTO `xadmin_log` VALUES (1,'2019-02-18 08:15:38.056795','127.0.0.1','117','admin | 日志记录 | 日志组','create','已添加。',2,7),(2,'2019-02-18 08:15:49.995311','127.0.0.1','1','test','create','已添加。',3,7);
/*!40000 ALTER TABLE `xadmin_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `xadmin_usersettings`
--

DROP TABLE IF EXISTS `xadmin_usersettings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `xadmin_usersettings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `key` varchar(256) NOT NULL,
  `value` longtext NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `xadmin_usersettings_user_id_edeabe4a_fk_tb_user_id` (`user_id`),
  CONSTRAINT `xadmin_usersettings_user_id_edeabe4a_fk_tb_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `xadmin_usersettings`
--

LOCK TABLES `xadmin_usersettings` WRITE;
/*!40000 ALTER TABLE `xadmin_usersettings` DISABLE KEYS */;
INSERT INTO `xadmin_usersettings` VALUES (1,'dashboard:home:pos','',7),(2,'site-theme','/static/xadmin/css/themes/bootstrap-xadmin.css',7);
/*!40000 ALTER TABLE `xadmin_usersettings` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `xadmin_userwidget`
--

DROP TABLE IF EXISTS `xadmin_userwidget`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `xadmin_userwidget` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `page_id` varchar(256) NOT NULL,
  `widget_type` varchar(50) NOT NULL,
  `value` longtext NOT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `xadmin_userwidget_user_id_c159233a_fk_tb_user_id` (`user_id`),
  CONSTRAINT `xadmin_userwidget_user_id_c159233a_fk_tb_user_id` FOREIGN KEY (`user_id`) REFERENCES `tb_users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `xadmin_userwidget`
--

LOCK TABLES `xadmin_userwidget` WRITE;
/*!40000 ALTER TABLE `xadmin_userwidget` DISABLE KEYS */;
/*!40000 ALTER TABLE `xadmin_userwidget` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2019-02-25  9:29:33
