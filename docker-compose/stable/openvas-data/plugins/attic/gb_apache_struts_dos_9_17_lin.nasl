# Copyright (C) 2017 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107239");
  script_version("2021-04-06T07:28:50+0000");
  script_cve_id("CVE-2017-9804");
  script_bugtraq_id(100612);
  script_tag(name:"last_modification", value:"2021-04-06 07:28:50 +0000 (Tue, 06 Apr 2021)");
  script_tag(name:"creation_date", value:"2017-09-11 14:24:03 +0200 (Mon, 11 Sep 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Apache Struts DoS Vulnerability (S2-050) - Linux");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100612");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-050");

  script_tag(name:"summary", value:"Apache Struts is prone to a regular expression Denial
  of Service (DoS) vulnerability when using URLValidator.

  This VT has been merged into the VT 'Apache Struts DoS Vulnerability (S2-050)'
  (OID: 1.3.6.1.4.1.25623.1.0.107240).");

  script_tag(name:"insight", value:"The previous fix issued with S2-047 was incomplete.
  If an application allows enter an URL in a form field and built-in URLValidator is used,
  it is possible to prepare a special URL which will be used to overload server process
  when performing validation of the URL.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause a DoS
  condition, denying service to legitimate users.");

  script_tag(name:"affected", value:"Apache Struts 2.3.7 through 2.3.33 and 2.5 through
  2.5.12.");

  script_tag(name:"solution", value:"Update to version 2.3.34, 2.5.13 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);