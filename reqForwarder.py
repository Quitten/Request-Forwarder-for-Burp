from burp import IBurpExtender
from burp import IInterceptedProxyMessage
from burp import IProxyListener

class BurpExtender(IBurpExtender, IProxyListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Request Forwarder")
        callbacks.registerProxyListener(self)
        self.hostsToDrop = ["google.com", "google.co.il" , "youtube.com", "google-analytics.com"]

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest:
            messageInfo = message.getMessageInfo()
            for hostToDrop in self.hostsToDrop:
                currentHost = messageInfo.getHttpService().getHost()
                if hostToDrop in currentHost:
                    # print "Request not intercepted for the url: " + str(self._helpers.analyzeRequest(messageInfo).getUrl())
                    message.setInterceptAction(IInterceptedProxyMessage.ACTION_DONT_INTERCEPT)
                    break
        return