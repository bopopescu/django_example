# -*- coding: utf-8 -*-
import os, sys, time, datetime, pstats, shutil, json, argparse, logging, stat, pathlib, string, random, qiniu, http, \
    threading, filetype, hashlib, re, pprint, ast
from functools import wraps, partial, lru_cache
from decorator import decorator
from enum import Enum
from collections import namedtuple, Counter, defaultdict, OrderedDict, deque
from django.contrib.auth import authenticate, logout, login
from django.contrib.auth.decorators import login_required, permission_required
from django.db.models.aggregates import Max, Count
from django.utils.timezone import make_aware
from django.db.models import F, Q
from DjangoCaptcha import Captcha
from django.views.generic import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.db import transaction
from django.db.utils import IntegrityError
from django.contrib.auth import models as djmodel
from django.http import QueryDict
from main.conf import default, local
from fengtai.utils import tools, error, requestForms, dbRouter
from main import common, models, tasks


@decorator
def operation(fun, request, actions, *args, **kwargs):
    """
        操作记录修饰方法
    :param fun:
    :return:
    """
    start = time.time()
    ret = fun(request, actions, *args, **kwargs)
    if default.debug:
        print(
            f"in the operation decorator {actions} {request.method} username:{request.user.username} use time {time.time()-start}")
    return ret


def identityCheckInfo(request):
    def getId(key, val):
        if not getattr(default, key, None):
            print(f"in the getId found {key} not in default")
            return None
        for k, v in getattr(default, key).items():
            if k == val:
                return v
        return None

    form = requestForms.IdentityForm(request.GET)
    if not form.is_valid():
        return tools.genErrorStatusResponse(error.status_formError)
    identity = form.cleaned_data['id']
    for it in models.BasicInfoOfOlder.objects.select_related('pensions', 'flag', 'locate_county', 'locate_street',
                                                             'locate_community').filter(identityCard=identity):
        dt = tools.BaseData()
        dt.name = it.name
        dt.gender = getId('gender', it.gender)
        dt.identityCard = it.identityCard
        dt.birthDay = it.birthDay.strftime('%Y%m%d') if it.birthDay else None
        dt.nationality = getId('nationality', it.nationality)
        dt.education = getId('education', it.education)
        dt.politics = getId('politics', it.politics)
        dt.marriageStatus = getId('marriageStatus', it.marriageStatus)
        dt.identityType = getId('identityType', it.identityType)
        dt.locate_community = it.locate_community.ora_name if it.locate_community else None
        dt.locate_street = it.locate_street.ora_name if it.locate_street else None
        dt.locate_county = it.locate_county.ora_name if it.locate_county else None
        dt.address = it.address
        dt.postcode = it.postcode
        dt.censusRegister = it.censusRegister
        dt.registerNature = getId('registerNature', it.registerNature)
        dt.emergencyPeople = it.emergencyPeople
        dt.emergencyPhone = it.emergencyPhone
        dt.pensions_bjtCard = it.pensions.bjtCard
        dt.pensions_bankCard = it.pensions.bankCard
        dt.pensions_insuranceType = getId('insuranceType', it.pensions.insuranceType)
        dt.pensions_medicalInsuranceType = getId('medicalInsuranceType', it.pensions.medicalInsuranceType)
        dt.pensions_insured = getId('insured', it.pensions.insured)
        dt.pensions_mininumLivingLevel = getId('mininumLivingLevel', it.pensions.mininumLivingLevel)
        dt.pensions_laborCapacity = getId('laborCapacity', it.pensions.laborCapacity)
        dt.pensions_employmentStatus = getId('employmentStatus', it.pensions.employmentStatus)
        dt.pensions_vocation = getId('vocation', it.pensions.vocation)
        dt.pensions_healthStatus = getId('healthStatus', it.pensions.healthStatus)
        dt.pensions_bodyStatus = getId('bodyStatus', it.pensions.bodyStatus)
        dt.pensions_residenceStatus = getId('residenceStatus', it.pensions.residenceStatus)
        dt.pensions_livingDegree = getId('livingDegree', it.pensions.livingDegree)
        dt.pensions_careType = getId('careType', it.pensions.careType)
        dt.pensions_economicSource = getId('economicSource', it.pensions.economicSource)
        dt.pensions_incomingLevel = getId('incomingLevel', it.pensions.incomingLevel)
        dt.flag_isObjectTraditional = getId('isObjectTraditional', it.flag.isObjectTraditional)
        dt.flag_isObjectServiced = getId('isObjectServiced', it.flag.isObjectServiced)
        dt.flag_isSpecialSalvation = getId('isSpecialSalvation', it.flag.isSpecialSalvation)
        dt.flag_isLonely = getId('isLonely', it.flag.isLonely)
        dt.flag_isDisabled = getId('isDisabled', it.flag.isDisabled)
        dt.flag_isNZJ = getId('isNZJ', it.flag.isNZJ)
        dt.flag_isReleased = getId('isReleased', it.flag.isReleased)
        dt.flag_isExservicee = getId('isExservicee', it.flag.isExservicee)
        dt.flag_isReservoirImmigrant = getId('isReservoirImmigrant', it.flag.isReservoirImmigrant)
        dt.flag_isAbroadRelative = getId('isAbroadRelative', it.flag.isAbroadRelative)
        dt.flag_isDeath = getId('isDeath', it.flag.isDeath)
        return tools.genErrorStatusResponse(error.status_200, **dt.toJson)
    return tools.genErrorStatusResponse(error.status_notFound)


# 用户登录相关
def userLogin(request):
    """
        用户登录
    :param request:
    :return:
    """
    form = requestForms.Login(request.POST)
    if not form.is_valid():
        print(f"in the form found error {form.errors}")
        return tools.genErrorStatusResponse(error.status_formError)
    username, password, verifyCode = form.cleaned_data['username'], form.cleaned_data['password'], form.cleaned_data[
        'verifyCode']
    cap = Captcha(request)
    if not cap.check(verifyCode):
        if default.debug:
            print(f"code check is invalid now {verifyCode}")
        return tools.genErrorStatusResponse(error.status_checkValueError)
    relPassword = tools.parsePassword(request, password)
    if default.debug:
        print("the username %s password %s %s" % (username, relPassword, password))
    if not relPassword:
        return tools.genErrorStatusResponse(error.status_needRedo)
    user = authenticate(username=username, password=relPassword)
    if user:
        if user.is_authenticated and user.is_active:
            if default.debug:
                print("in index user %s will login now " % (user.username))
            login(request, user)
            log = tools.BaseData()
            log.username, log.action = user.username, local.log_login.value
            tasks.logRecord.delay(log.toJson)
            return tools.genErrorStatusResponse(error.status_200, data=common.userPermission(user))
    return tools.genErrorStatusResponse(error.status_usernameOrPasswordError)


@login_required()
def userLogout(request):
    log = tools.BaseData()
    log.username, log.action = request.user.username, local.log_logout.value
    tasks.logRecord.delay(log.toJson)
    logout(request)
    return tools.genErrorStatusResponse(error.status_200)


@login_required()
def userNotification(request):
    """
        通知消息
    :param request:
    :return:
    """
    genre = request.user.groups.all()[0].genre
    if genre in {local.super.name, local.systemAdmin.name}:
        return tools.genErrorStatusResponse(error.status_200)
    else:
        ret_list = []
        for it in models.PolicyArt.objects.filter(
                Q(distribution__district__ora_index=request.user.locate.ora_index) & Q(articleStatus=2)).exclude(
            distribution__readers__user=request.user).values('title', 'articleid', "createTime"):
            data = tools.BaseData()
            data.title = it['title']
            data.articleid = it['articleid']
            data.createTime = it['createTime'].strftime("%Y-%m-%d %H:%M") if it['createTime'] else None
            ret_list.append(data.toJson)
        return tools.genErrorStatusResponse(error.status_200, ret_list)


@login_required()
def notificationDetail(request):
    """
        通知查看内容
    :param request:
    :return:
    """
    need = [local.polices.name, local.elderPolicy.name, local.lastestPolicy.name]
    for group in request.user.groups.all():
        ct = group.permissions.filter(codename__in=need)
        if len(ct) != len(need):
            return tools.genErrorStatusResponse(error.status_unAuthorized)
    return common.policyArticlePreview(request, detail=True)


@login_required()
def clearAllNotification(request):
    """
        清空用户通知
    :param request:
    :return:
    """
    if request.user.is_superuser:
        pass
    else:
        with dbRouter.in_database('slave'):
            for it in models.PolicyArt.objects.filter(
                    Q(distribution__district__ora_index=request.user.locate.ora_index) & Q(articleStatus=2)).exclude(
                distribution__readers__user=request.user).values('articleid').iterator():
                tasks.policyArticleStatistic.apply_async(args=[request.user.username, it['articleid']])
    return tools.genErrorStatusResponse(error.status_200)


def getSundries(request):
    """
        系统全局默认参数
    :param request:
    :return:
    """

    class Detail(tools.BaseData):
        pass

    dt = Detail()
    dt.pageSize = [i for i in default.defaultPageSize]
    # dt.status = [{'lable': v.value, 'value': k} for k, v in default.status.items()]
    # genre = request.user.groups.all()[0].genre
    # if genre in {local.super.name, local.systemAdmin.name}:
    #     dt.districtLevel = [{"label": v.value, "value": k} for k, v in default.belongs.items()]
    #     dt.roles = [{'label': k.value, 'value': k.name} for k in default.basicRoleGroup]
    # else:
    #     dt.districtLevel = []
    #     dt.roles = []
    #     found = False
    #     # 角色获取
    #     for group in request.user.groups.all():
    #         for item in common.menus.funcs:
    #             if found or item.name == group.genre:
    #                 found = True
    #                 dt.roles.append({'label': item.value, 'value': item.name})
    #     found = False
    #     # 行政级别获取
    #     for k, v in default.belongs.items():
    #         if found or k >= request.user.locate.ora_level:
    #             found = True
    #             dt.districtLevel.append({"label": v.value, "value": k})
    return tools.genErrorStatusResponse(error.status_200, **dt.toJson)


# 地区管理
class Districts(View, metaclass=tools.SingleInstance):
    @method_decorator([csrf_exempt, ])
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super(Districts, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if not self.action:
            return common.getDistrictList(request)
        else:
            if self.action == 'hierarchy':
                return common.getDistrictHierarchy(request)
            elif self.action == "level":
                return common.getDistrictLevel(request)
            elif self.action == 'detail':
                return common.detailDistrict(request)
            elif self.action == 'order':
                return common.districtOrder(request)
            elif self.action == 'dynamic':
                return common.districtDynamicSearch(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def post(self, request, *args, **kwargs):
        if not self.action:
            return common.districtUpdateOrCreate(request, created=True)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def put(self, request, *args, **kwargs):
        if self.action == 'detail':
            return common.districtUpdateOrCreate(request, created=False)
        elif self.action == 'order':
            return common.modifyDistrictOrder(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def delete(self, request, *args, **kwargs):
        return common.districtDelete(request)


# 角色
class Roles(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super(Roles, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if not self.action:
            return common.getRoles(request)
        elif self.action == 'genres':
            return common.getBasicGenres(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def post(self, request, *args, **kwargs):
        return common.roleUpdateOrCreate(request, created=True)

    def put(self, request, *args, **kwargs):
        return common.roleUpdateOrCreate(request, created=False)

    def delete(self, request, *args, **kwargs):
        return common.roleDelete(request)


# 用户
class Users(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super(Users, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if not self.action:
            return common.userLists(request)
        elif self.action == 'roles':
            return common.getUserRoles(request)
        elif self.action == "district":
            return common.getDistrictHierarchyForCreateUser(request)
        elif self.action == 'dynamic':
            return common.usersDynamicSearch(request)
        elif self.action == 'advancedDynamic':
            return common.userDynamicAdvancedSearch(request)
        elif self.action == 'advancedDynamicParam':
            return common.userAdvancedDynamicParam(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def put(self, request, *args, **kwargs):
        return common.updateOrCreateUser(request, created=False)

    def delete(self, request, *args, **kwargs):
        return common.deleteUser(request)

    def post(self, request, *args, **kwargs):
        return common.updateOrCreateUser(request, created=True)


# 个人中心
class personCenter(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super(personCenter, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return common.personalInfo(request)

    def put(self, request, *args, **kwargs):
        if not self.action:
            return common.updatePassword(request)
        elif self.action == 'myBasic':
            return common.modifyMyInfo(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)


class Logging(View, metaclass=tools.SingleInstance):

    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super(Logging, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if not self.action:
            return common.logList(request)
        elif self.action == 'detail':
            return common.detailLog(request)
        elif self.action == 'dynamic':
            return common.logDynamicSearch(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)


# 老人信息查询
class olderQuery(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action: str = kwargs['tail'] if kwargs['tail'] else None
        return super(olderQuery, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        # if self.action == 'streets':
        #     return common.getAllStreets(request)
        if self.action == 'communities':
            return common.getAllCommunites(request)
        elif self.action == 'conditions':
            return common.olderConditions(request)
        elif self.action == 'genAposChart':
            return common.genderAndPolitics_statistic(request)
        elif self.action == 'nationalityChart':
            return common.nationality_statistic(request)
        elif self.action == 'streetsChart':
            return common.peopleOfStreet_statistic(request)
        elif self.action == 'communityChart':
            return common.peopleOfCommunity_statistic(request)
        elif self.action == 'ageScope_statistic':
            return common.insurance_statistic(request)
        elif self.action == 'olderList':
            return common.olderList(request)
        elif self.action == 'olderDetail':
            return common.olderDetail(request)
        elif self.action == 'olderEditDetail':
            return common.olderInfoGetEdit(request)
        elif self.action == 'districtLevel':
            return common.olderDistrictLevel(request)
        elif self.action == 'olderForm':
            return common.olderBasicForm(request)
        elif self.action == "downLoadExportedData":
            return common.downLoadExportData(request)
        elif self.action == 'checkTaskStatus':
            return common.checkTaskStatus(request)
        elif self.action == 'exportDataCondition':
            return common.exportElderDataConditions(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def post(self, request, *args, **kwargs):
        if self.action == 'elder':
            return common.olderInfoUpdateOrCreate(request, created=True)
        elif self.action == 'exportTask':
            return common.exportElderData(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def put(self, request, *args, **kwargs):
        if self.action == 'elder':
            return common.olderInfoUpdateOrCreate(request, created=False)
        return tools.genErrorStatusResponse(error.status_notAllowed)


# 老人信息管理
class olderManage(olderQuery):
    pass


# 老健人康案,添加于2019-12-09,档
class olderHealthArchive(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super(olderHealthArchive, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if self.action == 'conditions':
            return common.olderHealthArchive_conditions(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)


# 老健数据显示
class olderDataVisual(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super(olderDataVisual, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if self.action == 'conditions':
            return common.olderHealthArchive_conditions(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)


# 机构查询
class InstitutionQuery(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super(InstitutionQuery, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if self.action == 'conditions':
            return common.institutionCondition(request)
        elif self.action == 'institutionList':
            return common.institutionsList(request)
        elif self.action == 'institutionDetail':
            return common.institutionDetail(request)
        elif self.action == 'institutionEditDetail':
            return common.institutionEditDetail(request)
        elif self.action == 'districtLevel':
            return common.institutionDistrictLevel(request)
        elif self.action == 'institutionForm':
            return common.institutionBasicForm(request)
        elif self.action == 'exportDataCondition':
            return common.exportElderDataConditions(request)
        elif self.action == "downLoadExportedData":
            return common.downLoadExportInstitutionData(request)
        elif self.action == 'checkTaskStatus':
            return common.checkTaskStatusForInstitution(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def post(self, request, *args, **kwargs):
        if self.action == 'institution':
            return common.institutionUpdateOrCreate(request, created=True)
        elif self.action == 'exportTask':
            return common.exportInstitutionData(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def put(self, request, *args, **kwargs):
        if self.action == 'institution':
            return common.institutionUpdateOrCreate(request, created=False)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def delete(self, request, *args, **kwargs):
        if self.action == 'institution':
            return common.institutionDeleteItem(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)


# 机构管理
class InstitutionManage(InstitutionQuery):
    pass


# 养老照料中心
class InstitutionCareCenter(View, metaclass=tools.SingleInstance):

    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        # 照料中心
        # institutionType = 1
        # 养老驿站
        # institutionType = 3
        self.institutionType = kwargs['institutionType']
        return super(InstitutionCareCenter, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if self.action == 'conditions':
            return common.careCenterCondition(request)
        elif self.action == "institutionList":
            return common.careCenterList(request, self.institutionType)
        return tools.genErrorStatusResponse(error.status_notAllowed)


# 养老养老驿站
class InstitutionElderStation(InstitutionCareCenter):
    pass


# 养老财政投入
class FinancialQuery(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super(FinancialQuery, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if self.action == "condition":
            return common.financialCondition(request)
        elif self.action == "pineChart":
            return common.financialPineChart(request)
        elif self.action == 'histogramChart':
            return common.financialHistogramChart(request)
        elif self.action == 'projectList':
            return common.financialList(request)
        elif self.action == 'projectDetail':
            return common.financialDetail(request)
        elif self.action == 'basicForm':
            return common.FinancialBasicForm(request)
        elif self.action == 'projectEditDetail':
            return common.financialEditDetail(request)
        elif self.action == 'dynamic':
            return common.financialDynamicSearch(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def delete(self, request, *args, **kwargs):
        if self.action == 'financial':
            return common.financialDeleteItem(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def put(self, request, *args, **kwargs):
        if self.action == 'financial':
            return common.financialUpdateOrCreate(request, created=False)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def post(self, request, *args, **kwargs):
        if self.action == 'financial':
            return common.financialUpdateOrCreate(request, created=True)
        return tools.genErrorStatusResponse(error.status_notAllowed)


# 养老财政管理
class FinancialManage(FinancialQuery):
    pass


# 政策发布
class PolicyRelease(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super(PolicyRelease, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if self.action == 'districtLevel':
            return common.policyArticleDistrictLevel(request)
        elif self.action == 'download':
            return common.policyDownloadAccessories(request)
        elif self.action == 'preview':
            return common.policyArticlePreview(request)
        elif self.action == 'articleList':
            return common.policyArticleList(request)
        elif self.action == 'publish':
            return common.policyArticlePublish(request)
        elif self.action == 'revocation':
            return common.policyArticleRevocation(request)
        elif self.action == 'statisticChart':
            return common.policyArticleChart(request)
        elif self.action == 'statisticList':
            return common.policyArticleStatisticList(request)
        elif self.action == 'lastArticles':
            return common.policyPublishList(request)
        elif self.action == 'articleDetail':
            return common.policyArticleDetail(request)
        elif self.action == "editPage":
            return common.policyArticleEditPage(request)
        elif self.action == 'dynamic':
            # 丰管理页的搜索
            return common.policyDynamicSearch(request)
        elif self.action == 'manageDynamic':
            # 管理页的搜索
            return common.policyDynamicSearch(request, managed=True)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def post(self, request, *args, **kwargs):
        if self.action == 'article':
            return common.policyArticleUpdateOrCreate(request, created=True)
        elif self.action == 'accessories':
            return common.policyArticleUpload(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def put(self, request, *args, **kwargs):
        if self.action == 'article':
            return common.policyArticleUpdateOrCreate(request, created=False)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def delete(self, request, *args, **kwargs):
        if self.action == 'accessories':
            return common.pollicyAccessoriesDelete(request)
        elif self.action == 'article':
            return common.policyArtDelete(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)


# 最新养老政策
class LastePolicy(PolicyRelease):
    pass


# 首页内容处理
class HomeContent(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if self.action == 'lastArticles':
            return common.policyPublishList(request)
        elif self.action == 'articleDetail':
            return common.policyArticleDetail(request)
        elif self.action == 'download':
            return common.policyDownloadAccessories(request)
        elif self.action == "activities":
            return common.homeGetActivities(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)


# 养老地图
class DataMap(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        self.pageSize = 300
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if self.action == 'elder_lng_lat':
            return common.dataMapElderPosition(request)
        elif self.action == 'institution_lng_lat':
            return common.institutionMapPosition(request, {2, 1}, self.pageSize)
        elif self.action == 'careCenter_lng_lat':
            return common.institutionMapPosition(request, {1, }, self.pageSize)
        elif self.action == 'elderStation_lng_lat':
            return common.institutionMapPosition(request, {3, }, self.pageSize)
        elif self.action == 'stationList':
            return common.institutionMapPosition(request, {1, 2, 3}, self.pageSize)
        return tools.genErrorStatusResponse(error.status_notAllowed)


# 呼叫中心
class CallCenterManage(View, metaclass=tools.SingleInstance):
    def dispatch(self, request, *args, **kwargs):
        self.action = kwargs['tail'] if kwargs['tail'] else None
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        if self.action == 'recordList':
            return common.callCenterRecordList(request)
        elif self.action == "recordDetail":
            return common.callcenterRecordDetail(request)
        elif self.action == 'dynamic':
            return common.callcenterDynamicSearch(request)
        elif self.action == "downLoadExportedData":
            return common.downLoadExportData(request)
        elif self.action == 'checkTaskStatus':
            return common.checkTaskStatus(request)
        elif self.action == 'exportDataCondition':
            return common.exportElderDataConditions(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)

    def post(self, request, *args, **kwargs):
        if self.action == "exportTask":
            return common.exportCallcenterData(request)
        return tools.genErrorStatusResponse(error.status_notAllowed)
