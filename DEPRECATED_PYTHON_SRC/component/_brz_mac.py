import os

def default_browser():    
    import LaunchServices
    import CoreData

    brzs = ["safari", "chrome", "firefox"]
    
    url = CoreData.CFURLRef.URLWithString_("http://www.google.com")
    os_status, app_ref, _ = LaunchServices.LSGetApplicationForURL(url, LaunchServices.kLSRolesAll, None, None)
    if os_status != 0:
        return None
    apppath = app_ref.as_pathname()
    name = os.path.basename(apppath).lower()
    for brz in brzs:
        if brz in name:
            return brz
    return None

def iterate_browsers(default=None):
    default = default_browser()
    browsers = []
    if os.path.exists("/Applications/Google Chrome.app"):
        browsers.append((
            "chrome",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            default=="chrome",
            False,
        ))
    if os.path.exists("/Applications/Firefox.app"):
        browsers.append((
            "firefox",
            "/Applications/Firefox.app/Contents/MacOS/firefox",
            default=="firefox",
            False,
        ))
    # It is not easy to setup proxy programmatically without use authorization.
    #
    if os.path.exists("/Applications/Safari.app"):
        browsers.append((
            "safari",
            "open -a Safari",
            default=="safari",
            False,
        ))        
    return browsers
