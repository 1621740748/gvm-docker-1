# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.144399");
  script_version("2021-03-30T14:16:33+0000");
  script_tag(name:"last_modification", value:"2021-03-30 14:16:33 +0000 (Tue, 30 Mar 2021)");
  script_tag(name:"creation_date", value:"2020-08-17 02:27:52 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-0230", "CVE-2019-0233");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts 2.x < 2.5.22 Multiple Vulnerabilities (S2-059, S2-060) - Linux");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");

  script_tag(name:"summary", value:"Apache Struts is prone to multiple vulnerabilities.

  This VT has been merged into the VT 'Apache Struts 2.x < 2.5.22 Multiple Vulnerabilities
  (S2-059, S2-060)' (OID: 1.3.6.1.4.1.25623.1.0.144400).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2019-0230: Forced double OGNL evaluation, when evaluated on raw user input in tag
  attributes, may lead to remote code execution.

  - CVE-2019-0233: Access permission override causing a denial of service when performing
  a file upload.");

  script_tag(name:"affected", value:"Apache Struts 2.0.0 through 2.5.20.");

  script_tag(name:"solution", value:"Update to version 2.5.22 or later.");

  script_xref(name:"URL", value:"https://struts.apache.org/announce.html#a20200813");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-059");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-060");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);