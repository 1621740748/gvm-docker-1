###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for kernel FEDORA-2018-2ee3411cb8
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
  script_oid("1.3.6.1.4.1.25623.1.0.875201");
  script_version("2021-06-09T11:00:19+0000");
  script_tag(name:"last_modification", value:"2021-06-09 11:00:19 +0000 (Wed, 09 Jun 2021)");
  script_tag(name:"creation_date", value:"2018-10-17 06:39:38 +0200 (Wed, 17 Oct 2018)");
  script_cve_id("CVE-2018-14633", "CVE-2018-17182", "CVE-2018-5391", "CVE-2018-15471",
                "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-14734", "CVE-2018-14678",
                "CVE-2018-13405", "CVE-2018-13053", "CVE-2018-12896", "CVE-2018-13093",
                "CVE-2018-13094", "CVE-2018-13095", "CVE-2018-12714", "CVE-2018-12633",
                "CVE-2018-12232", "CVE-2018-10853", "CVE-2018-11506", "CVE-2018-10840",
                "CVE-2018-3639", "CVE-2018-1120", "CVE-2018-10322", "CVE-2018-10323",
                "CVE-2018-1108", "CVE-2018-10021", "CVE-2017-18232", "CVE-2018-7995",
                "CVE-2018-8043", "CVE-2018-7757", "CVE-2018-5803", "CVE-2018-1065",
                "CVE-2018-1000026", "CVE-2018-5750", "CVE-2018-1000004", "CVE-2018-5344",
                "CVE-2018-5332", "CVE-2018-5333", "CVE-2017-17862", "CVE-2017-17863",
                "CVE-2017-17864", "CVE-2017-17852", "CVE-2017-17853", "CVE-2017-17854",
                "CVE-2017-17855", "CVE-2017-17856", "CVE-2017-17857", "CVE-2017-17741",
                "CVE-2017-17712", "CVE-2017-17449", "CVE-2017-17450", "CVE-2017-17448",
                "CVE-2017-17558", "CVE-2017-8824", "CVE-2017-1000405", "CVE-2017-16649",
                "CVE-2017-16650", "CVE-2017-16644", "CVE-2017-16647", "CVE-2017-15115",
                "CVE-2017-16532", "CVE-2017-16538", "CVE-2017-12193", "CVE-2018-17972");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-21 12:16:00 +0000 (Tue, 21 Aug 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for kernel FEDORA-2018-2ee3411cb8");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
 on the target host.");
  script_tag(name:"affected", value:"kernel on Fedora 27");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"FEDORA", value:"2018-2ee3411cb8");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ACX4WW5ZZ3PNMAEPZVJGMZ2D2BYHVMUD");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC27");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "FC27")
{

  if ((res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.13~100.fc27", rls:"FC27")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
