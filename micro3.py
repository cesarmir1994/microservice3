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

#chromedriver_path = '/app/chromedriver'
chromedriver_path = '/usr/bin/chromedriver'
DOWNLOAD = 1
NO_DOWNLOAD = 2
INVALID = -1
p = None
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

def InputArgs():
    logger.debug("Comprobate the input arguments")
    try:
        assert len(sys.argv)==2, 'ERROR: You do not ingress 2 arguments'
    except Exception as error:
        logger.error(error)
        log('InputArgs', error)


#This funciton comprobate the http_status of the url
def get_status_code(url):
    try:
        logger.debug('The url begin to comprobate')
        urllib.request.urlopen(url, timeout=120)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            reason = 'Privacy policy unavailable'
            logger.error("Privacy policy download failed",
                         extra={'apk': p, 'exception_message': str(e), 'exit_code': e.code,
                                'container': 'downloader', 'testing_label': TESTING_LABEL})
            return False, e.code
        else:
            return True, e.code
    except urllib.error.URLError as e:
        reason = 'Cannot connect to the domain server'
        logger.error("Privacy policy download failed",
                     extra={'apk': p, 'exception_message': str(e), 'reason': reason, 'url': url,
                            'container': 'downloader', 'testing_label': TESTING_LABEL})
        return False, e.reason
    except Exception as e:
        reason = 'Timeout in urllib.request.urlopen'
        logger.error("Privacy policy download failed", extra={
            'apk': p, 'exception_message': str(e), 'reason': reason, 'url': url,
            'container': 'downloader', 'testing_label': TESTING_LABEL})
        return False, str(e)
    else:
        logger.info('The url comprobaton was sucessful')
        return True, 200

# This function is used to extract the text from web pages
def download_general_text(url):
    policy_text = None
    policy_html = None
    title = 'PP'
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
                     extra={'apk': p, 'exception_message': str(e), 'reason': reason,
                            'container': 'downloader', 'testing_label': TESTING_LABEL})
    except Exception as e:
        reason = "Error while downloading with Selenium"
        logger.error("Privacy policy download failed",
                     extra={'apk': p, 'exception_message': str(e), 'reason': reason,
                            'container': 'downloader', 'testing_label': TESTING_LABEL})
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
                     extra={'apk': p, 'exception_message': str(e), 'reason': reason,
                            'container': 'downloader', 'testing_label': TESTING_LABEL})
    else:
        logger.info('The extraction of text and html was successful')
        return policy_text, soup
# This funciton download the pdf con webisetes(expcep Google Drive, Onedrive, dropbox)
def download_pdf(url):
    try:
        logger.debug('The download pdf was started')
        responde = requests.get(url, stream = True)
        file = open('pp.pdf', 'wb')
        for chunk in responde.iter_content(chunk_size = 1024):
            if chunk:
                file.write(chunk)

    except Exception as error:
        logger.error('An error occurs during dowloaing pdf : '+error)
    else:
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
        file = open(title + ".txt", "w")
        file.write(policytxt)
        logger.debug("The privacy policy text was write")
        file.close()
        file = open(title + ".html", "w")
        file.write(policyhtml)
        logger.debug("The privacy policy html was write")
        file.close()
    except Exception as error:
        logger.error(error)

    else:
        logger.info('The text was stored')

#
# def url_classifier(url):
#     try:
#
#     except Exception as error:
#         logger.error(error)
#----------------------------------------------------------------
#                       MAIN CODE
#----------------------------------------------------------------
#Comprobation of input arguments for the execute

InputArgs()

url = sys.argv[1]

state, code = get_status_code(url)

download_pdf(url)

# url Normal
# google.drive ////view
#pText, pHtml, title = download_general_text(url)
#store_text(pText, pHtml, title)

# Google docs
#pText, pHtml = download_google_doc(url)
#store_google_doc(pText, pHtml)

# Drive

# if state == True or code == 200:
#     pText, pHtml, title = download_general_text(url)
#     store_privacy_policy(pText, pHtml, title)

print(state)

print(code)
