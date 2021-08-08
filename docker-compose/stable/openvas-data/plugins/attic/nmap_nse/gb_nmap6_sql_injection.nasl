###############################################################################
# OpenVAS Vulnerability Test
#
# Autogenerated NSE wrapper
#
# Authors:
# NSE-Script: Eddie Bell
# NASL-Wrapper: autogenerated
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803541");
  script_version("2020-07-07T14:13:50+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-07 14:13:50 +0000 (Tue, 07 Jul 2020)");
  script_tag(name:"creation_date", value:"2013-02-28 19:00:30 +0530 (Thu, 28 Feb 2013)");
  script_name("Nmap NSE 6.01: sql-injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2013 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");

  script_tag(name:"summary", value:"Spiders an HTTP server looking for URLs containing queries vulnerable to an SQL injection attack.

The script spiders an HTTP server looking for URLs containing queries. It then proceeds to combine
crafted SQL commands with susceptible URLs in order to obtain errors. The errors are analysed to see
if the URL is vulnerable to attack. This uses the most basic form of SQL injection but anything more
complicated is better suited to a standalone tool.

We may not have access to the target web server's true hostname, which can prevent access to
virtually hosted sites.

SYNTAX:

httpspider.withinhost:  only spider URLs within the same host.
(default: true)

httpspider.maxpagecount:  the maximum amount of pages to visit.
A negative value disables the limit (default: 20)

httpspider.withindomain:  only spider URLs within the same
domain. This widens the scope from 'withinhost' and can
not be used in combination. (default: false)

httpspider.maxdepth:  the maximum amount of directories beneath
the initial url to spider. A negative value disables the limit.
(default: 3)

httpspider.url:  the url to start spidering. This is a URL
relative to the scanned host eg. /default.html (default: /)

sql-injection.start:  The path at which to start spidering, default '/'.

http.pipeline:  If set, it represents the number of HTTP requests that'll be
pipelined (ie, sent in a single request). This can be set low to make
debugging easier, or it can be set high to test how a server reacts (its
chosen max is ignored).

sql-injection.maxdepth:  The maximum depth to spider, default 10.

http-max-cache-size:  The maximum memory size (in bytes) of the cache.

httpspider.noblacklist:  if set, doesn't load the default blacklist");

  script_tag(name:"solution_type", value:"Mitigation");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
