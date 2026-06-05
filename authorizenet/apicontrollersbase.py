'''
Created on Nov 1, 2015

@author: krgupta
'''
import abc
import logging
import pyxb
import re
import sys
import xml.dom.minidom
import requests
from lxml import objectify

from authorizenet.constants import constants
from authorizenet import apicontractsv1
from authorizenet import utility
'''
from authorizenet.apicontractsv1 import merchantAuthenticationType
from authorizenet.apicontractsv1 import ANetApiRequest
from authorizenet.apicontractsv1 import ANetApiResponse
'''

anetLogger = logging.getLogger(constants.defaultLoggerName)
anetLogger.addHandler(logging.NullHandler())
logging.getLogger('pyxb.binding.content').addHandler(logging.NullHandler())

# Sensitive XML elements that should be fully masked in logs (credentials/secrets)
_FULLY_MASKED_TAGS = [
    'transactionKey',
    'cardCode',
    'pin',
    'password',
]

# Sensitive XML elements that should be partially masked (show last 4 chars)
_PARTIAL_MASKED_TAGS = [
    'cardNumber',
    'accountNumber',
    'routingNumber',
    'expirationDate',
    'bankAccountNum',
    'bankRoutingNum',
    'creditCardNumberMasked',
    'bankAccountNumberMasked',
]

def _mask_partial(value, visible_chars=4):
    """Mask a value showing only the last N characters."""
    if not value or len(value) <= visible_chars:
        return 'XXXX'
    return 'X' * (len(value) - visible_chars) + value[-visible_chars:]

def _sanitize_xml_for_logging(xml_string):
    """
    Sanitize XML string by masking sensitive fields before logging.
    This prevents PCI-sensitive data and API credentials from being exposed in logs.
    - Credentials (transactionKey, cardCode, pin, password): Fully masked
    - Card/Account numbers: Partial masked (last 4 visible, e.g., XXXXXXXXXXXX1111)
    """
    if xml_string is None:
        return xml_string
    
    sanitized = xml_string if isinstance(xml_string, str) else xml_string.decode('utf-8')
    
    # Fully mask credentials and secrets
    for tag in _FULLY_MASKED_TAGS:
        pattern = r'(<{0}>)[^<]*(</{0}>)'.format(tag)
        sanitized = re.sub(pattern, r'\1[REDACTED]\2', sanitized)
    
    # Partially mask card/account numbers (show last 4)
    for tag in _PARTIAL_MASKED_TAGS:
        pattern = r'<{0}>([^<]*)</{0}>'.format(tag)
        def make_replacer(tag_name):
            def replacer(match):
                value = match.group(1)
                masked = _mask_partial(value)
                return '<{0}>{1}</{0}>'.format(tag_name, masked)
            return replacer
        sanitized = re.sub(pattern, make_replacer(tag), sanitized)
    
    return sanitized

class APIOperationBaseInterface(object):
    
    __metaclass__ = abc.ABCMeta
    
    @abc.abstractmethod
    def execute(self):
        '''
        Makes a http-post call. 
        Uses request xml and response class type to check that the response was of correct type
        '''
        pass

    @abc.abstractmethod
    def getresponseclass(self):
        ''' Returns the response class '''
        pass
    
    @abc.abstractmethod
    def getrequesttype(self):
        ''' Returns the request class '''
        pass
    
    @abc.abstractmethod
    def getresponse(self):
        ''' Returns the de-serialized response'''
        pass
    
    @abc.abstractmethod
    def getresultcode(self):
        ''' Returns the result code from the response '''
        pass
    
    @abc.abstractmethod
    def getmessagetype(self):
        ''' Returns the message type enum from the response '''
        pass

    @abc.abstractmethod
    def afterexecute(self):
        '''Returns the message received from binding after processing request'''
        pass

    @abc.abstractmethod
    def beforeexecute(self):
        '''TODO'''
        pass

class APIOperationBase(APIOperationBaseInterface):
    
    __metaclass__ = abc.ABCMeta 
    __initialized = False
    __merchantauthentication = "null"
    __environment = "null"
    
    @staticmethod
    def __classinitialized():
        return APIOperationBase.__initialized
    
    @abc.abstractmethod
    def validaterequest(self):
        return
    
    def validate(self):
        anetapirequest = self._getrequest()
        self.validateandsetmerchantauthentication()       
        self.validaterequest()
        
        return

    def setClientId(self): #protected method
        self._request.clientId = constants.clientId

    def _getrequest(self): #protected method
        return self._request 
     
    def buildrequest(self):
        anetLogger.debug('building request..')
        
        xmlRequest = self._request.toxml(encoding=constants.xml_encoding, element_name=self.getrequesttype())
        #remove namespaces that toxml() generates
        xmlRequest = xmlRequest.replace(constants.nsNamespace1, b'')
        xmlRequest = xmlRequest.replace(constants.nsNamespace2, b'')

        return xmlRequest
    
    def getprettyxmlrequest(self):
        xmlRequest = self.buildrequest()
        requestDom = xml.dom.minidom.parseString(xmlRequest)
        anetLogger.debug('Request is: %s' % _sanitize_xml_for_logging(requestDom.toprettyxml()))

        return requestDom
    
    def execute(self):
        
        self.endpoint = APIOperationBase.__environment
              
        anetLogger.debug('Executing http post to url: %s', self.endpoint)
        
        self.beforeexecute()
        
        proxyDictionary = {'http' : utility.helper.getproperty("http_proxy"),
                           'https' : utility.helper.getproperty("https_proxy"),
                           'ftp' : utility.helper.getproperty("ftp")}
                           
        #requests is http request  
        try:
            self.setClientId()
            xmlRequest = self.buildrequest()
            self._httpResponse = requests.post(self.endpoint, data=xmlRequest, headers=constants.headers, proxies=proxyDictionary)
        except Exception as httpException:
            anetLogger.error( 'Error retrieving http response from: %s for request: %s', self.endpoint, _sanitize_xml_for_logging(self.buildrequest()))
            anetLogger.error( 'Exception: %s, %s', type(httpException), httpException.args )


        if self._httpResponse:            
            self._httpResponse.encoding = constants.response_encoding
            self._httpResponse = self._httpResponse.text[3:] #strip BOM
            self.afterexecute()
            try:
                self._response = apicontractsv1.CreateFromDocument(self._httpResponse) 
                #objectify code  
                xmlResponse= self._response.toxml(encoding=constants.xml_encoding, element_name=self.getrequesttype()) 
                xmlResponse = xmlResponse.replace(constants.nsNamespace1, b'')
                xmlResponse = xmlResponse.replace(constants.nsNamespace2, b'') 
                self._mainObject = objectify.fromstring(xmlResponse)   
                 
            except Exception as objectifyexception:
                anetLogger.error( 'Create Document Exception: %s, %s', type(objectifyexception), objectifyexception.args )
                responseString = self._httpResponse

                # removing encoding attribute as objectify fails if it is present
                responseString = responseString.replace('encoding=\"utf-8\"', '')
                self._mainObject = objectify.fromstring(responseString) 
            else:
                if type(self.getresponseclass()) != type(self._mainObject):
                    if self._response.messages.resultCode == "Error":
                        anetLogger.debug("Response error")
                    domResponse = xml.dom.minidom.parseString(self._httpResponse.encode('utf-8'))
                    anetLogger.debug('Received response: %s' % domResponse.toprettyxml(encoding='utf-8'))
                else:
                    #Need to handle ErrorResponse  
                    anetLogger.debug('Error retrieving response for request: %s' % self._request)
        else:
            anetLogger.debug("Did not receive http response")
        return
    
    def getresponse(self):
        #return self._response #pyxb object
        return self._mainObject #objectify object
    
    def getresultcode(self):
        resultcode = 'null'
        if self._response:
            resultcode = self._response.resultCode
        return resultcode
    
    def getmessagetype(self):
        message = 'null'
        if self._response:
            message = self._response.message
        return message
    
    def afterexecute(self ):
        return 
    
    def beforeexecute(self):
        return 
    
    @staticmethod
    def getmerchantauthentication(self):
        return self.__merchantauthentication
    
    @staticmethod
    def setmerchantauthentication(merchantauthentication):
        APIOperationBase.__merchantauthentication = merchantauthentication
        return
    
    def validateandsetmerchantauthentication(self):
        anetapirequest = apicontractsv1.ANetApiRequest()
        if (anetapirequest.merchantAuthentication == "null"):
            if (self.getmerchantauthentication() != "null"):
                anetapirequest.merchantAuthentication = self.getmerchantauthentication()
            else:
                raise ValueError('Merchant Authentication can not be null')
        return
    
    @staticmethod
    def getenvironment(self):
        return APIOperationBase.__environment
        
    
    @staticmethod
    def setenvironment(userenvironment):
        APIOperationBase.__environment = userenvironment 
        return 
    
    def __init__(self, apiRequest):
        self._httpResponse = None
        self._request = None
        self._response = None
        #objectify variables 
        self._responseXML = None
        self._reponseObject = None
        self._mainObject = None
               
        if None == apiRequest:
            raise ValueError('Input request cannot be null')
         
        self._request = apiRequest
        __merchantauthentication = apicontractsv1.merchantAuthenticationType()
        APIOperationBase.__environment = constants.SANDBOX
        
        APIOperationBase.setmerchantauthentication(__merchantauthentication)
        self.validate()
            
        return
