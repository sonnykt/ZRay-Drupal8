The Symfony plugin extends Z-Ray to display Symfony information on all the various Symfony elements constructing the page, including bundles, events, and listeners, together with general information on the setup and the request.
The Symfony plugin also defines the routing logic for Symfony requests - for better events aggregation in Zend Server, and improved results for URLs in URL Insight.

*   Bundles
    *   Lists all the used Symfony bundles on the page, with information on the bundle name, its namespace and container and the source file path.
*   Events
    *   Lists all the Symfony events that were triggered by the request, with information on the event name, the event type, the event dispatcher, and an indication on whether propagation was stopped or not.
*   Listeners
    *   Lists all the Symfony event listeners used on the page, with information on the associated event.
*   Request
    *   Shows general data on the request, including:
*   Security
    *   Displays useful information on authentication and authorization, including an indication on whether security is enabled or not, usernames and passwords, and information on used access tokens.