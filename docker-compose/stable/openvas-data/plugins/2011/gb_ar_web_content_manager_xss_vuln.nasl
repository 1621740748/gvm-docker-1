###############################################################################
# OpenVAS Vulnerability Test
#
# AR Web Content Manager (AWCM) 'search.php' Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801911");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2011-1668");
  script_bugtraq_id(47126);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("AR Web Content Manager (AWCM) 'search.php' Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=179");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47126/");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_AWCM_XSS.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to execute arbitrary HTML
  code in a user's browser session in the context of a vulnerable application.");

  script_tag(name:"affected", value:"AWCM CMS version 2.2 and prior");

  script_tag(name:"insight", value:"Input passed via the 'search' parameter in 'search' action in search.php is not
  properly verified before it is returned to the user. This can be exploited
  to execute arbitrary HTML and script code in a user's browser session in the
  context of a vulnerable site. This may allow an attacker to steal cookie-based
  authentication credentials and launch further attacks.");

  script_tag(name:"solution", value:"Apply the patch from below link.");

  script_tag(name:"summary", value:"The host is running AR Web Content Manager (AWCM) and is prone to Cross-Site
  Scripting vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name:"URL", value:"http://www.zshare.net/download/8818096688e1e96a/");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

awcmPort = http_get_port(default:80);

foreach dir (make_list_unique("/awcm", "/AWCM", "/", http_cgi_dirs(port:awcmPort))) {

  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache(item:dir + "/index.php", port:awcmPort);

  if(">AWCM" >< rcvRes)
  {
    if(http_vuln_check(port:awcmPort, url:dir + '/search.php?search=<script>' +
                       'alert("XSS-Test")</script>&where=all',
                       pattern:'(<script>alert."XSS-Test".</script>)', check_header:TRUE))
    {
      security_message(port:awcmPort);
      exit(0);
    }
  }
}

exit(99);
