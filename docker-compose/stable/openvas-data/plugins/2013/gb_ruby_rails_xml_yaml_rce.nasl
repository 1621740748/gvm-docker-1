###############################################################################
# OpenVAS Vulnerability Test
#
# Ruby on Rails XML Processor YAML Deserialization RCE Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

CPE = "cpe:/a:rubyonrails:rails";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802050");
  script_version("2020-07-14T14:24:25+0000");
  script_bugtraq_id(57187);
  script_cve_id("CVE-2013-0156");
  script_tag(name:"last_modification", value:"2020-07-14 14:24:25 +0000 (Tue, 14 Jul 2020)");
  script_tag(name:"creation_date", value:"2013-01-18 11:03:52 +0530 (Fri, 18 Jan 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Ruby on Rails XML Processor YAML Deserialization RCE Vulnerability");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_rails_consolidation.nasl");
  script_mandatory_keys("rails/http/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51753");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/24019");
  script_xref(name:"URL", value:"http://www.insinuator.net/2013/01/rails-yaml");
  script_xref(name:"URL", value:"http://ronin-ruby.github.com/blog/2013/01/09/rails-pocs.html");
  script_xref(name:"URL", value:"http://blog.codeclimate.com/blog/2013/01/10/rails-remote-code-execution-vulnerability-explained");
  script_xref(name:"URL", value:"https://community.rapid7.com/community/metasploit/blog/2013/01/09/serialization-mischief-in-ruby-land-cve-2013-0156");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary commands.");

  script_tag(name:"affected", value:"Ruby on Rails before 2.3.15, 3.0.x before 3.0.19, 3.1.x before 3.1.10,
  and 3.2.x before 3.2.11.");

  script_tag(name:"insight", value:"Flaw is due to an error when parsing XML parameters, which allows symbol
  and yaml types to be a part of the request and can be exploited to execute arbitrary commands.");

  script_tag(name:"solution", value:"Upgrade to Ruby on Rails 2.3.15, 3.0.19, 3.1.10, 3.2.11, or later.");

  script_tag(name:"summary", value:"The host is installed with Ruby on Rails and is prone to a remote
  command execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(port:port, cpe:CPE))
  exit(0);

if(dir == "/")
  dir = "";

useragent = http_get_user_agent();
host = http_host_name(port:port);

url = dir + "/posts/search";

req_common = string("POST ", url, " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", useragent, "\r\n",
                    "Content-Type: application/xml\r\n");
post_data1 = string('<?xml version="1.0" encoding="UTF-8"?>\r\n',
                    '<probe type="string"><![CDATA[\r\n', 'hello\r\n',
                    ']]></probe>');
req1 = string(req_common, "Content-Length: ", strlen(post_data1), "\r\n\r\n", post_data1);
res1 = http_send_recv(port:port, data:req1);

# nb: Ignore if http status code starts with 4 or 5
if(!res1 || egrep(pattern:"^HTTP/1\.[01] [45][0-9][0-9]", string:res1))
  exit(0);

post_data2 = string('<?xml version="1.0" encoding="UTF-8"?>\r\n',
                    '<probe type="yaml"><![CDATA[\r\n',
                    '--- !ruby/object:Time {}\r\n','\r\n', ']]></probe>');
req2 = string(req_common, "Content-Length: ", strlen(post_data2), "\r\n\r\n", post_data2);
res2 = http_send_recv(port:port, data:req2);

# nb: Continue if http status code starts with 2 or 3
if(egrep(pattern:"^HTTP/1\.[01] [23][0-9][0-9]", string:res2)) {
  post_data3 = string('<?xml version="1.0" encoding="UTF-8"?>\r\n',
                      '<probe type="yaml"><![CDATA[\r\n',
                      '--- !ruby/object:\x00\r\n', ']]></probe>');
  req3 = string(req_common, "Content-Length: ", strlen(post_data3), "\r\n\r\n", post_data3);
  res3 = http_send_recv(port:port, data:req3);
  if(egrep(pattern:"^HTTP/1\.[01] 200", string:res3)) {
    report = http_report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(0);
