###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_2180_gnupg2_centos6.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for gnupg2 CESA-2018:2180 centos6
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882922");
  script_version("2021-05-26T06:00:13+0200");
  script_tag(name:"last_modification", value:"2021-05-26 06:00:13 +0200 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2018-07-14 05:51:53 +0200 (Sat, 14 Jul 2018)");
  script_cve_id("CVE-2018-12020");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for gnupg2 CESA-2018:2180 centos6");
  script_tag(name:"summary", value:"Check the version of gnupg2");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The GNU Privacy Guard (GnuPG or GPG) is a
  tool for encrypting data and creating digital signatures, compliant with OpenPGP
  and S/MIME standards.

Security Fix(es):

  * gnupg2: Improper sanitization of filenames allows for the display of fake
status messages and the bypass of signature verification (CVE-2018-12020)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.");
  script_tag(name:"affected", value:"gnupg2 on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"CESA", value:"2018:2180");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-July/022966.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"gnupg2", rpm:"gnupg2~2.0.14~9.el6_10", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gnupg2-smime", rpm:"gnupg2-smime~2.0.14~9.el6_10", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
