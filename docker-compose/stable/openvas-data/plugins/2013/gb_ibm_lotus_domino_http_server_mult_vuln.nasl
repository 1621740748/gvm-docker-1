###############################################################################
# OpenVAS Vulnerability Test
#
# IBM Lotus Domino HTTP Server Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803187");
  script_version("2020-09-22T09:01:10+0000");
  script_tag(name:"last_modification", value:"2020-09-22 09:01:10 +0000 (Tue, 22 Sep 2020)");
  script_tag(name:"creation_date", value:"2013-03-27 14:56:20 +0530 (Wed, 27 Mar 2013)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2012-3301", "CVE-2012-3302", "CVE-2012-4842", "CVE-2012-4844");
  script_bugtraq_id(55095, 58152);

  script_name("IBM Lotus Domino HTTP Server Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50330");
  script_xref(name:"URL", value:"http://securityvulns.ru/docs28474.html");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/77401");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79233");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Sep/55");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21614077");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21608160");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hcl_domino_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hcl/domino/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML or
  web script in a user's browser session in context of an affected site, compromise the application and access
  web server configuration information.");

  script_tag(name:"affected", value:"IBM Lotus Domino 7.x and 8.x before 8.5.4.");

  script_tag(name:"insight", value:"- Input appended to the URL after servlet/ is not properly sanitized before
    being returned to the user.

  - Input passed via the 'Src' parameter to MailFS and WebInteriorMailFS is not
    properly sanitized before being returned to the user.

  - Input passed via the 'RedirectTo' parameter to names.nsf?Login is not
    properly sanitized before being returned to the user.

  - The 'domcfg.nsf' page is accessible without authentication, there is a
    leakage of information about web server configuration.");

  script_tag(name:"solution", value:"Update to IBM Lotus Domino 8.5.4 or later.");

  script_tag(name:"summary", value:"Lotus Domino HTTP Server is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit(0);

if( dir == "/" )
  dir = "";

url = dir + "/domcfg.nsf";

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"Web Server Configuration",
                     extra_check: make_list( "NotesView", "_domino_name" ) ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
