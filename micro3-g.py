# ------------------------------------------------------------------
#	                    IMPORTANT LIBRARIES
# ------------------------------------------------------------------
import imp
import sys
import urllib
import subprocess
import os
import time
import json
import multiprocessing
import ast
import urllib.request, urllib.error
import re
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException, NoSuchElementException
from tika import parser
from bs4 import BeautifulSoup
from bs4.element import Comment
import requests
from requests.exceptions import HTTPError
from tld import get_tld
import fnmatch
import random
import docx2txt
# --------------------------------------------------
#                   GLOBAL VARIABLES
# --------------------------------------------------
chromedriver_path = '/app/chromedriver'
# chromedriver_path = '/usr/bin/chromedriver'
result_dir = 'result/'
# ------------------------------------------------------------------
#                     LOG CONFIGURATION
# ------------------------------------------------------------------
import logging as log
from pythonjsonlogger import jsonlogger
handler = None
logger = None
# log agent initialization
def init_logger(file):
    global handler, logger
    handler = log.FileHandler(file)
    format_str = '%(levelname)s%(asctime)s%(filename)s%(funcName)s%(lineno)d%(message)'
    formatter = jsonlogger.JsonFormatter(format_str)
    handler.setFormatter(formatter)
    logger = log.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(log.DEBUG)
    return logger
# log agent termination
def stop_logger():
    logger.removeHandler(handler)
    handler.close()
# log agent definition
logger = init_logger('logs.privapp.log')
# ---------------------------------------------------------------------------------------
#                     FUNCTIONS FOR MICROSERVICE 3
# ---------------------------------------------------------------------------------------
# Function to obtain the domain od url
def get_bag_of_targeted_domains(domain):
    # Getting "bag of domains" of targeted domains
    try:
        logger.debug('get_bag_of_package_domains function has been started')
        res = get_tld(domain, fix_protocol=True, as_object=True, fail_silently=True)
        bag_of_targeted_domains = []
        if res is not None:
            bag_of_targeted_domains.append(res.domain)
            if res.subdomain != '':
                bag_of_targeted_domains.extend(res.subdomain.split('.'))
    except Exception as e:
        reason = 'get_bag_of_targeted_domains unavailable'
        logger.error('bag of domains failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.info('get_bag_of_package_domains function has been successful')
        return [d for d in bag_of_targeted_domains if d not in ['www']]
#Function to determinate if the url is pdf document
def is_pdf_web(url):
    try:
        if fnmatch.fnmatch(url, '*.pdf'):
            return True
        else:
            return False
    except Exception as e:
        reason = 'is_pdf_web unavailable'
        logger.error('is_pdf_web failed',
                     extra={'exception_message': str(e), 'reason': reason})
# Function to determine similarities
def url_matching(url, token):
    try:
        url_token = get_bag_of_targeted_domains(url)
        common_elements = set(url_token) & set(token)
        if len(common_elements) != 0:
            flag = True
        else:
            flag = False
    except Exception as e:
        reason = 'url_matching unavailable'
        logger.error('url_matching failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        return flag
# Function to determine the membership of the url to a website
def url_selector(url):
    try:
        csf_html = False
        # To download pdf from common web page
        csf_pdf = is_pdf_web(url)
        # To download the docs format document from google docs website
        token_docs = ['docs']
        csf_docs = url_matching(url, token_docs)
        # To download the txt format file from drive website
        token_drive = ['drive']
        csf_drive = url_matching(url, token_drive)
        # To download the txt, html, doc, docx and pdf format file from drive website
        token_dropbox = ['dropbox']
        csf_dropbox = url_matching(url, token_dropbox)
        # To download the docx format document from onedrive website
        token_onedrive = ['onedrive', 'live']
        csf_onedrive = url_matching(url, token_onedrive)
        # if it is not any of the special cases, it is considered a web page of
        if csf_pdf == False and csf_onedrive == False and \
                csf_drive == False and csf_dropbox == False and csf_docs == False:
            logger.info('Because it does not match any of the website domains under '
                        'consideration, it is categorized by default as an HTML page.')
            csf_html = True
    except Exception as e:
        reason = 'url_selector unavailable'
        logger.error('url_selector failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('The function was successful')
        return csf_pdf, csf_docs, csf_drive, csf_html, csf_dropbox, csf_onedrive
# Function to determine if the url can be downloaded
def is_downloable(csf_pdf, csf_docs, csf_drive, csf_html, csf_dropbox, csf_onedrive):
    try:
        if csf_onedrive == True :
            logger.info('This site was considerate only for docx documents')
            download_flag = False
        elif csf_pdf == True or csf_docs == True or csf_drive == True or \
                csf_html == True or csf_dropbox == True:
            logger.info('This sites was considerate')
            download_flag = True
    except Exception as e:
        reason = 'is_downloable unavailable'
        logger.error('is_downloable failed',
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.info('is_downloable function has been successful')
        return download_flag
# This funciton comprobate the http_status of the url
def get_status_code(url):
    headers = {'User-Agent':
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'}
    try:
        req = urllib.request.Request(url, data=None, headers=headers)
        urllib.request.urlopen(req, timeout=120)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            reason = 'Privacy policy unavailable'
            logger.error("Privacy policy download failed",
                         extra={'exception_message': str(e),
                                'reason': reason, 'exit_code': e.code})
            return False, e.code
        else:
            return True, e.code
    except urllib.error.URLError as e:
        reason = 'Cannot connect to the domain server'
        logger.error("Privacy policy download failed",
                     extra={'exception_message': str(e),
                            'reason': reason, 'url': url})
        return False, e.reason
    except Exception as e:
        reason = 'Timeout in urllib.request.urlopen'
        logger.error("Privacy policy download failed", extra={
            'exception_message': str(e), 'reason': reason, 'url': url})
        return False, str(e)
    else:
        return True, 200
# This function is used to extract the text from web pages
def download_general_text(url):
    policy_text = None
    policy_html = None
    TIMEOUT = 60
    TIMERSLEEP = 30
    chromeOptions = webdriver.ChromeOptions()
    # Define options for the web browser
    chromeOptions.add_argument("--no-sandbox")
    chromeOptions.add_argument("--enable-javascript")
    chromeOptions.add_argument("--headless")
    chromeOptions.add_argument('--disable-dev-shm-usage')
    n_ram = random.randrange(10, 100, 4)
    titulo = 'PolicyPrivacy'
    # Set the options
    driver = webdriver.Chrome(executable_path=r'{}'
                              .format(chromedriver_path), options=chromeOptions)
    try:
        logger.debug('The webdriver was being started')
        WebDriverWait(driver, TIMEOUT).until(EC.presence_of_element_located(
            (By.TAG_NAME, "html")))
        # Get the HTML code from the page
        driver.get(url)
        time.sleep(TIMERSLEEP)
        # Get the HTML code from the page
        element = driver.find_element_by_tag_name('html')
        # Extract text from the attribute innerText
        policy_text = element.get_attribute('innerText')
        policy_html = driver.page_source
        title = (driver.title).replace(" ", "")
        if title == None:
            title = titulo
        title += str(n_ram)
    except TimeoutException as e:
        reason = "HTML element has not been load after {} seconds".format(TIMEOUT)
        logger.error("Privacy policy download failed",
                     extra={'exception_message': str(e), 'reason': reason})
    except Exception as e:
        reason = "Error while downloading with Selenium"
        logger.error("Privacy policy download failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.info('The extraction of text and html has been successful')
        return policy_text, policy_html, title
    finally:
        driver.close()
# This function was used to download google docs
def download_google_doc(url):
    policy_text = ""
    policy_html = ""
    try:
        logger.debug('download_google_doc function has been started')
        html = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(html, 'html.parser')
        aux_title = soup.title.text
        aux2_title = aux_title.split('-')[0]
        title = aux2_title.replace(' ', '')
        policy_html = str(soup)
        js_text_lst = soup.find_all('script', type='text/javascript')
        for js_text in js_text_lst:
            js_text = str(js_text)
            # Splitting and filtering the text matching with [XXXXX].
            for text in re.findall("\[.+\]", js_text):
                #  We processes only visible text getting segments containing this
                #  pattern {"ty":"is", ...}. They are identifiers of google doc contents
                if text is not None and '"ty":"is"' in text:
                    text = text.replace('true', 'True')
                    text = text.replace('false', 'False')
                    text = text.replace('null', 'None')
                    policy_text += ast.literal_eval(text)[0]['s']
                    # 's' is the key used by google docs to identify the text
    except Exception as e:
        reason = 'Extraction of privacy policy text from google docs failed'
        logger.error("Privacy policy download failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.info('download_google_doc function has been successful')
        return policy_text, policy_html, title
# This funciton download the pdf con websites(expcep Google Drive, Onedrive, dropbox)
def download_pdf(url):
    try:
        logger.debug('download_pdf function has been started')
        n_ram = random.randrange(10, 100, 4)
        pdf_name = 'privacyPolicy' + str(n_ram)
        response = requests.get(url, stream=True, verify=False)
        file = open(result_dir + pdf_name + '.pdf', 'wb')
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                file.write(chunk)
    except Exception as e:
        reason = 'Error while downloading pdf documento from the web'
        logger.error("download_pdf download failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.info('ownload_pdf function has been started successful')
        return pdf_name
    finally:
        file.close()
# This function downloads the docx document from the onedrive website
def download_onedrive_docx(url):
    try:
        logger.debug('Download of docx document has started')
        response = requests.get(url)
        html = response.content
        soup = BeautifulSoup(html, 'html.parser')
        policy_html = (str(soup))
        # get tittle

        aux_titulo = soup.title.text
        aux2_titulo = aux_titulo.split('-')[0]
        titulo = aux2_titulo.replace('.', '_')
        file_name = titulo.replace(' ', '')

        # filter the url
        tag = '"FileGetUrl"'
        lines = policy_html.split('\n')
        aux = [x for x in lines if x.startswith('var $Config=')]
        url_text = aux[0].split(tag)[1].split('"')[1]
        # replace special strings in the url
        if url_text is not None and 'https' in url_text:
            url_text = url_text.replace('\\u003a', ':')
            url_text = url_text.replace('\\u002f', '/')
            url_text = url_text.replace('\\u003f', '/')
            url_text = url_text.replace('\\u0026', '&')
            url_text = url_text.replace('\\u003d', '=')
        aux_response = requests.get(url_text, stream=True, verify=False)
        file = open(result_dir + file_name + '.docx', 'wb')
        for chunk in aux_response.iter_content(chunk_size=1024):
            if chunk:
                file.write(chunk)
        file.close()
        policy_text = docx2txt.process(result_dir + file_name + '.docx')
    except Exception as e:
        reason = 'Error while downloading docx document from onedrive'
        logger.error("download_pdf download failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.info('The docx download was successful')
        return policy_text, policy_html, file_name
#This function stores html document
def OD_html_store(file_name, url_text):
    try:
        logger.debug('The download html document from dropbox was start')
        response = requests.get(url_text)
        html = response.content
        soup = BeautifulSoup(html, 'html.parser')
        policy_html = soup.find('body').pre.text
        soup = BeautifulSoup(policy_html, 'html.parser')
        policy_text = soup.find('body').text
        file = open(result_dir + file_name + '.txt', "w")
        file.write(policy_text)
        file.close()
        file = open(result_dir + file_name + '.html', "w")
        file.write(policy_html)
        file.close()
    except Exception as e:
        reason = 'Error while downloading html documento from dropbox'
        logger.error("download_pdf download failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('The download html documento from dropbox was successful')
#This function stores txt document
def OD_text_store(file_name, url_text):
    try:
        logger.debug('The download txt document from dropbox was start')
        response = requests.get(url_text)
        html = response.content
        soup = BeautifulSoup(html, 'html.parser')
        policy_html = (str(soup))
        policy_text = soup.find('body').pre.text
        file = open( result_dir + file_name + '.txt', "w")
        file.write(policy_text)
        file.close()
        file = open( result_dir + file_name + '.html', "w")
        file.write(policy_html)
        file.close()
    except Exception as e:
        reason = 'Error while downloading txt documento from dropbox'
        logger.error("download_pdf download failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('The download txt document from dropbox was successful')
#This function filter url from html response
def OD_filtrado(policyhtml, tag):
    url_text = None
    aux = None
    try:
        logger.debug('OD_filtrado function has been started')
        lines = policyhtml.split('\n')
        aux = [x for x in lines if x.startswith('InitReact.mountComponent')]
        url_text = aux[0].split(tag)[1].split('"')[1]
    except Exception as e:
        reason = 'Error while filter url from dropbox'
        logger.error("download_pdf download failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('OD_filtrado function has been successful')
        return url_text
#This function stores pdf document
def OD_pdf_store(file_name, url_text, url):
    try:
        logger.debug('The download document from dropbox was start')
        response = requests.get(url)
        html = response.content
        soup = BeautifulSoup(html, 'html.parser')
        policy_html = (str(soup))
        file = open( result_dir + file_name + '.html', "w")
        file.write(policy_html)
        file.close()
        response = requests.get(url_text, stream=True, verify=False)
        file = open( result_dir + file_name + '.pdf', 'wb')
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                file.write(chunk)
    except Exception as e:
        reason = 'Error while downloading txt documento from dropbox'
        logger.error("download_pdf download failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('Download text document from dropbox was successful')
        file.close()
#This function extracts text content from pdf document
def pdf2text(file_name):
    try:
        logger.debug('Text extraction from PDF document started')
        raw = parser.from_file( result_dir + file_name+'.pdf')
        content = raw['content']
        file = open( result_dir + file_name + ".txt", "w")
        file.write(content)
        file.close()
    except Exception as e:
        reason = 'Error while extract text from pdf document'
        logger.error("download_pdf download failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('Extraction of text from a PDF document was successful')
#This function enables download document from dropbox website
def dropbox_general(url):
    tag = None
    aux_titulo = None
    try:
        logger.debug('The download document from dropbox has been started')
        response = requests.get(url)
        html = response.content

        soup = BeautifulSoup(html, 'html.parser')
        aux_titulo = soup.title.text
        aux2_titulo = aux_titulo.replace(' ', '')
        titulo = aux2_titulo.split('-')[1]
        titulo = titulo.replace('.', '_')
        formato = aux2_titulo.split('-')[1].split('.')[1]
        policyhtml = (str(soup))
        file_name = titulo + str(random.randrange(10, 100, 4))
        logger.debug('by executing the appropriate method for the format '+str(formato))

        tag = '"preview_url"'
        url_text = OD_filtrado(policyhtml, tag)
        if formato == 'html':
            OD_html_store(file_name, url_text)
        elif formato == 'txt':
            OD_text_store(file_name, url_text)
        elif formato == 'docx' or formato == 'doc' or \
                formato == 'rtf'or formato == 'pdf':
            OD_pdf_store(file_name, url_text, url)
            pdf2text(file_name)
    except Exception as e:
        reason = 'Error while downloading documento from dropbox'
        logger.error("download_pdf download failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.debug('Document download from Dropbox was successful')
# This function stores the text from web pages
def store_text(policytxt, policyhtml, title):
    try:
        logger.debug('store_text function has been started')
        file = open(result_dir + title + ".txt", "w")
        file.write(policytxt)
        file.close()
        file = open(result_dir + title + ".html", "w")
        file.write(policyhtml)
        file.close()
    except Exception as e:
        reason = 'store_text function unviable'
        logger.error("store_text failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        logger.info('store_text function has been successful')
# This function can list element from a list
def apk_list(path):
    try:
        data = []
        with open(path) as fname:
            lines = fname.readlines()
            for line in lines:
                data.append(line.strip('\n'))
    except Exception as e:
        reason = 'apk_list unviable'
        logger.error("apk_list failed",
                     extra={'exception_message': str(e), 'reason': reason})
    else:
        return data
# ----------------------------------------------------------------
#                       MAIN CODE
# ----------------------------------------------------------------
def Service3():
    print('Entering microservice 3')
    path = input()
    elements = apk_list(path)
    cont = 0
    for url in elements:
        cont = cont + 1
        print(cont)
        print(url)
        logger.info('Running the microservice 3')
        try:
            [state, code] = get_status_code(url)
            logger.info(str(state) + ' , ' + str(code))
            if state == True and code == 200:
                logger.info('The state and code was right')
                [csf_pdf, csf_docs, csf_drive, csf_html, csf_dropbox, csf_onedrive] = url_selector(url)
                downloadFlag = is_downloable(csf_pdf, csf_docs, csf_drive, csf_html, csf_dropbox, csf_onedrive)
                if downloadFlag == True:
                    logger.debug('The download is possible')
                    if csf_drive or csf_html:
                        print('Downloading web document')
                        pText, pHtml, title = download_general_text(url)
                        store_text(pText, pHtml, title)
                    if csf_pdf:
                        print('Downloading pdf document')
                        pdf_name = download_pdf(url)
                        pdf2text(pdf_name)
                    if csf_docs:
                        print('Downloading google docs document')
                        pText, pHtml, title = download_google_doc(url)
                        store_text(pText, pHtml, title)
                    if csf_dropbox:
                        print('Downloading documents from Dropbox')
                        dropbox_general(url)
                elif downloadFlag == False:
                    logger.info('This case can be download docx from OneDrive')
                    if csf_onedrive:
                        print('Downloading docx document from OneDrive')
                        pText, pHtml, title = download_onedrive_docx(url)
                        store_text(pText, pHtml, title)
            else:
                    logger.info('Problems with the URL response')
                    print('Problems with the url state')
        except Exception as e:
            print('Error while microservice 3')
            reason = 'main service unviable'
            logger.error("main service failed",
                         extra={'exception_message': str(e), 'reason': reason})
        else:
            print('The Privacy Policy download has ended')
            print('-------------------------------------------------------')
            print()
    logger.info('Leaving microservice 3')
#
# Running microservice 3
#
Service3()
logger = stop_logger()
