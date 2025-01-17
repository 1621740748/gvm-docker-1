###############################################################################
# OpenVAS Vulnerability Test
#
# Lotus Domino Src and BaseTarget XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:lotus_domino";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19764");
  script_version("2020-09-22T09:01:10+0000");
  script_tag(name:"last_modification", value:"2020-09-22 09:01:10 +0000 (Tue, 22 Sep 2020)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2005-3015");
  script_bugtraq_id(14845, 14846);

  script_name("Lotus Domino Src and BaseTarget XSS");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_hcl_domino_consolidation.nasl", "cross_site_scripting.nasl");
  script_mandatory_keys("hcl/domino/detected");
  script_require_ports("Services/www", 80);

  script_tag(name:"solution", value:"Upgrade to Domino 6.5.2 or newer.");

  script_tag(name:"summary", value:"The remote host runs Lotus Domino web server
  which is vulnerable to multiple cross-site scripting due to a lack of
  sanitization of user-supplied data.");

  script_tag(name:"impact", value:"Successful exploitation of
  this issue may allow an attacker to execute malicious script code in a
  user's browser within the context of the affected application.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

host = http_host_name(dont_add_port:TRUE);
if(http_get_has_generic_xss(port:port, host:host))
  exit(0);

r = http_get_cache(item:"/", port:port);
if(!r)
  exit(0);

matches = egrep(pattern:'src=.+(.+?OpenForm.+BaseTarget=)', string:r);
foreach match(split(matches)) {
  match = chomp(match);
  matchspec = eregmatch(pattern:'src="(.+?OpenForm.+BaseTarget=)', string:match);
  if(!isnull(matchspec)) {
    url = string(matchspec[1], '";+<script>alert(foo)</script>;+var+mit="a');
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if(!res)
      continue;

    if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(foo)</script>" >< res) {
      report = http_report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
    }
  }
}

exit(0);
