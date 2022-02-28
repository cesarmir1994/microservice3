#------------------------------------------------------------------
#	                    LIBRARIES IMPORT
#------------------------------------------------------------------
import imp
import sys
import argparse
import urllib
import subprocess
import pika
import os
import json
import time
import multiprocessing
import requests
import ast
import urllib.request, urllib.error
import re
from subprocess import call
import logging as log
from pythonjsonlogger import jsonlogger
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


#chromedriver_path = '/app/chromedriver'
chromedriver_path = '/usr/bin/chromedriver'
result_dir = 'result/'
#------------------------------------------------------------------
#                     LOG CONFIGURATION
#------------------------------------------------------------------

handler = None
logger = None

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


def stop_logger():
	logger.removeHandler(handler)
	handler.close()
logger = init_logger('log.json')

#---------------------------------------------------------------------------------------
#                     FUNTIONS FOR MICROSERVICE 3
#---------------------------------------------------------------------------------------

def get_bag_of_targeted_domains(domain):
    # Getting "bag of domains" of targeted domains
    res = get_tld(domain, fix_protocol=True, as_object=True, fail_silently=True)
    bag_of_targeted_domains = []
    if res is not None:
        bag_of_targeted_domains.append(res.domain)

        if res.subdomain != '':
            bag_of_targeted_domains.extend(res.subdomain.split('.'))

    return [d for d in bag_of_targeted_domains if d not in ['www']]


def is_pdf_stored(url):
    if fnmatch.fnmatch(url, '*.pdf*'):
        return True
    else:
        return False

def is_pdf_web(url):
    if fnmatch.fnmatch(url, '*.pdf'):
        return True
    else:
        return False

def url_matching(url, token):
    try:
        url_token = get_bag_of_targeted_domains(url)
        common_elements = set(url_token) & set(token)
        if len(common_elements) != 0:
            return True
        else:
            return False

    except Exception as error:
        print('Error')

def url_selector():
    try:
        logger.debug('begining')
        csf_html = False
        csf_pdf = is_pdf_web(url)
        token_docs = ['docs']
        csf_docs = url_matching(url, token_docs)
        token_drive = ['drive']
        csf_drive = url_matching(url, token_drive)
        token_dropbox = ['dropbox']
        csf_dropbox = url_matching(url, token_dropbox)
        token_onedrive = ['onedrive', 'live']
        csf_onedrive = url_matching(url, token_onedrive)
        if csf_pdf == False and csf_onedrive == False and \
                csf_drive == False and csf_dropbox == False and csf_docs == False:
            csf_html = True

    except Exception as error:
        logger.error(error)
    else:
        logger.debug('sucessful')
        return csf_pdf, csf_docs, csf_drive, csf_html, csf_dropbox, csf_onedrive

def is_downloable(csf_pdf, csf_docs, csf_drive, csf_html, csf_dropbox, csf_onedrive):
    try:
        logger.debug('Begining')
        if csf_onedrive == True or csf_dropbox == True:
            logger.info('This case was considerate')
            download_flag = False

        if csf_pdf == True or csf_docs == True or csf_drive == True or csf_html == True:
            logger.info('This case was not considerate')
            download_flag = True

    except Exception as error:
        logger.error(error)
    else:
        logger.info('successful')
        return download_flag


def InputArgs():
    logger.debug("Comprobate the input arguments")
    try:
        assert len(sys.argv)==2, 'ERROR: You do not ingress 2 arguments'
    except Exception as error:
        logger.error(error)


#This funciton comprobate the http_status of the url
def get_status_code(url):
    try:
        logger.debug('The url begin to comprobate')
        urllib.request.urlopen(url, timeout=120)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            reason = 'Privacy policy unavailable'
            logger.error("Privacy policy download failed",
                         extra={'exception_message': str(e), 'exit_code': e.code,
                                'container': 'downloader'})
            return False, e.code
        else:
            return True, e.code
    except urllib.error.URLError as e:
        reason = 'Cannot connect to the domain server'
        logger.error("Privacy policy download failed",
                     extra={'exception_message': str(e), 'reason': reason, 'url': url,
                            'container': 'downloader'})
        return False, e.reason
    except Exception as e:
        reason = 'Timeout in urllib.request.urlopen'
        logger.error("Privacy policy download failed", extra={
            'exception_message': str(e), 'reason': reason, 'url': url,
            'container': 'downloader'})
        return False, str(e)
    else:
        logger.info('The url comprobaton was sucessful')
        return True, 200

# This function is used to extract the text from web pages
def download_general_text(url):
    policy_text = None
    policy_html = None
    title = 'PolicyPrivacy'
    TIMEOUT = 60
    TIMERSLEEP = 30
    chromeOptions = webdriver.ChromeOptions()
    #Define option for the navegator
    chromeOptions.add_argument("--no-sandbox")
    chromeOptions.add_argument("--enable-javascript")
    chromeOptions.add_argument("--headless")
    chromeOptions.add_argument('--disable-dev-shm-usage')
    #Set the option
    driver = webdriver.Chrome(executable_path=r'{}'.format(chromedriver_path), options=chromeOptions)
    try:
        logger.debug('The web driver was being started')
        WebDriverWait(driver, TIMEOUT).until(EC.presence_of_element_located((By.TAG_NAME, "html")))
        # Get the HTML code from the page
        driver.get(url)
        time.sleep(TIMERSLEEP)
        # Get the HTML code from the page
        element = driver.find_element_by_tag_name('html')
        #Extract text from the attribute innerText
        policy_text = element.get_attribute('innerText')
        title = (driver.title).replace(" ", "")
        policy_html = driver.page_source
        
    except TimeoutException as e:
        reason = "HTML element has not been load after {} seconds".format(TIMEOUT)
        logger.error("Privacy policy download failed",
                     extra={'exception_message': str(e), 'reason': reason,
                            'container': 'downloader'})
    except Exception as e:
        reason = "Error while downloading with Selenium"
        logger.error("Privacy policy download failed",
                     extra={'exception_message': str(e), 'reason': reason,
                            'container': 'downloader'})
    finally:
        driver.close()
        logger.info('The extraction of text and html was successful')
        return policy_text, policy_html, title

# This function was used to download google docs
def download_google_doc(url):
    policy_text = ""
    soup = ""
    try:
        logger.debug('The web funtion was being started')
        html = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(html, 'html.parser')
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
                    policy_text += ast.literal_eval(text)[0][
                        's']  # 's' is the key used by google docs to identify the text
    except Exception as e:
        policy_text = None
        reason = 'Extraction of privacy policy text from google docs failed'
        logger.error("Privacy policy download failed",
                     extra={'exception_message': str(e), 'reason': reason,
                            'container': 'downloader'})
    else:
        logger.info('The extraction of text and html was successful')
        return policy_text, soup
# This funciton download the pdf con webisetes(expcep Google Drive, Onedrive, dropbox)
def download_pdf(url):
    try:
        logger.debug('The download pdf was started')
        n_ram = random.randrange(10, 100, 4)
        pdf_name = 'PolicyPrivacy'+str(n_ram)
        responde = requests.get(url, stream = True, verify = False)
        file = open(result_dir+pdf_name+'.pdf', 'wb')
        for chunk in responde.iter_content(chunk_size = 1024):
            if chunk:
                file.write(chunk)

    except Exception as error:
        reason = 'Eror while downloading pdf documento from the web'
        logger.error("The PDF Privacy policy download failed",
                     extra={'exception_message': str(error), 'reason': reason,
                            'container': 'downloader'})
    else:
        pdf_name += '.pdf'
        command =  "pdftotext " + result_dir+pdf_name
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=None, shell=True)
        logger.info('The pdf download was successful')
#This function stored the text and html code from google docs
def store_google_doc(policy_text, policy_html):
    try:
        logger.debug('The doc started to be stored ')
        file = open("PP.txt", "w")
        file.write(policy_text)
        file.close()
        try:
            with open("PP.txt") as f:
                titulo = f.readlines()[0]
                f.close()
            os.rename("PP.txt", titulo + ".txt")
        except Exception as e:
            logger.error('Unexpectated error during changed name of files')

        file = open(titulo + ".html", "w")
        file.write(str(policy_html))
        logger.debug("The privacy policy html was write")
        file.close()
    except Exception as error :
        logger.error(error)
    else:
        logger.info('The google doc was stored')

def store_text(policytxt, policyhtml, title):
    try:
        logger.debug('The text started to be stored ')
        file = open(result_dir+title + ".txt", "w")
        file.write(policytxt)
        logger.debug("The privacy policy text was write")
        file.close()
        file = open(result_dir+title + ".html", "w")
        file.write(policyhtml)
        logger.debug("The privacy policy html was write")
        file.close()
    except Exception as error:
        logger.error(error)

    else:
        logger.info('The text was stored')


#----------------------------------------------------------------
#                       MAIN CODE
#----------------------------------------------------------------
#Comprobation of input arguments for the execute

InputArgs()

url = sys.argv[1]

[state, code] = get_status_code(url)
if state == True and code == 200:
    logger.info('The state and code was right')
    [csf_pdf, csf_docs, csf_drive, csf_html, csf_dropbox, csf_onedrive] = url_selector()
    downloadFlag = is_downloable(csf_pdf, csf_docs, csf_drive, csf_html, csf_dropbox, csf_onedrive)
    if downloadFlag == True:
        logger.debug('The download is possible')
        if csf_drive or csf_html:
            print('Descargando el documento google Drive o HTML')
            pText, pHtml, title = download_general_text(url)
            store_text(pText, pHtml, title)
        if csf_pdf:
            print('Descargando el documento pdf')
            download_pdf(url)
        if csf_docs:
            print('Descargando el documento Google docs')
            pText, pHtml = download_google_doc(url)
            store_google_doc(pText, pHtml)
    else:
        logger.debug('The download is not possible')
else:
    logger.info('The status and code was not right, review thw url')





