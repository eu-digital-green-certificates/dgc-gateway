/*-
 * ---license-start
 * EU Digital Green Certificate Gateway Service / dgc-gateway
 * ---
 * Copyright (C) 2021 T-Systems International GmbH and all other contributors
 * ---
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ---license-end
 */

package eu.europa.ec.dgc.gateway.service;

import eu.europa.ec.dgc.gateway.entity.ValuesetEntity;
import eu.europa.ec.dgc.gateway.repository.ValuesetRepository;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class RatValuesetUpdateServiceTest {

    @Autowired
    RatValuesetUpdateService ratValuesetUpdateService;

    @Autowired
    ValuesetRepository valuesetRepository;

    @Test
    void testService() {
        ValuesetEntity vs = new ValuesetEntity(
            "covid-19-lab-test-manufacturer-and-name",
            new String(Base64.getDecoder().decode("ew0KICAidmFsdWVTZXRJZCI6ICJjb3ZpZC0xOS1sYWItdGVzdC1tYW51ZmFjdHVyZXItYW5kLW5hbWUiLA0KICAidmFsdWVTZXREYXRlIjogIjIwMjEtMDUtMjciLA0KICAidmFsdWVTZXRWYWx1ZXMiOiB7DQogICAgIjE4MzMiOiB7DQogICAgICAiZGlzcGxheSI6ICJBQVotTE1CLCBDT1ZJRC1WSVJPIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTE3IDExOjAyOjEyIENFVCINCiAgICB9LA0KICAgICIxMjMyIjogew0KICAgICAgImRpc3BsYXkiOiAiQWJib3R0IFJhcGlkIERpYWdub3N0aWNzLCBQYW5iaW8gQ09WSUQtMTkgQWcgUmFwaWQgVGVzdCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xNyAxMTowMTo0MiBDRVQiDQogICAgfSwNCiAgICAiMTQ2OCI6IHsNCiAgICAgICJkaXNwbGF5IjogIkFDT04gTGFib3JhdG9yaWVzLCBJbmMsIEZsb3dmbGV4IFNBUlMtQ29WLTIgQW50aWdlbiByYXBpZCB0ZXN0IiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDIwOjA3OjMwIENFVCINCiAgICB9LA0KICAgICIxMzA0Ijogew0KICAgICAgImRpc3BsYXkiOiAiQU1FREEgTGFib3JkaWFnbm9zdGlrIEdtYkgsIEFNUCBSYXBpZCBUZXN0IFNBUlMtQ29WLTIgQWciLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTM6MDQ6MDAgQ0VUIg0KICAgIH0sDQogICAgIjE4MjIiOiB7DQogICAgICAiZGlzcGxheSI6ICJBbmJpbyAoWGlhbWVuKSBCaW90ZWNobm9sb2d5IENvLiwgTHRkLCBSYXBpZCBDT1ZJRC0xOSBBbnRpZ2VuIFRlc3QoQ29sbG9pZGFsIEdvbGQpIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDE5OjQwOjE0IENFVCINCiAgICB9LA0KICAgICIxODE1Ijogew0KICAgICAgImRpc3BsYXkiOiAiQW5odWkgRGVlcCBCbHVlIE1lZGljYWwgVGVjaG5vbG9neSBDby4sIEx0ZCwgQ09WSUQtMTkgKFNBUlMtQ29WLTIpIEFudGlnZW4gVGVzdCBLaXQgKENvbGxvaWRhbCBHb2xkKSAtIE5hc2FsIFN3YWIiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTIgMTI6Mjc6NDYgQ0VUIg0KICAgIH0sDQogICAgIjE3MzYiOiB7DQogICAgICAiZGlzcGxheSI6ICJBbmh1aSBEZWVwIEJsdWUgTWVkaWNhbCBUZWNobm9sb2d5IENvLiwgTHRkLCBDT1ZJRC0xOSAoU0FSUy1Db1YtMikgQW50aWdlbiBUZXN0IEtpdChDb2xsb2lkYWwgR29sZCkiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTk6NDA6MTQgQ0VUIg0KICAgIH0sDQogICAgIjc2OCI6IHsNCiAgICAgICJkaXNwbGF5IjogIkFyY0RpYSBJbnRlcm5hdGlvbmFsIEx0ZCwgbWFyaVBPQyBTQVJTLUNvVi0yIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTE5IDE3OjEyOjEyIENFVCINCiAgICB9LA0KICAgICIxNjU0Ijogew0KICAgICAgImRpc3BsYXkiOiAiQXNhbiBQaGFybWFjZXV0aWNhbCBDTy4sIExURCwgQXNhbiBFYXN5IFRlc3QgQ09WSUQtMTkgQWciLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTk6NDA6MTQgQ0VUIg0KICAgIH0sDQogICAgIjIwMTAiOiB7DQogICAgICAiZGlzcGxheSI6ICJBdGxhcyBMaW5rIFRlY2hub2xvZ3kgQ28uLCBMdGQuLCBOT1ZBIFRlc3TCriBTQVJTLUNvVi0yIEFudGlnZW4gUmFwaWQgVGVzdCBLaXQgKENvbGxvaWRhbCBHb2xkIEltbXVub2Nocm9tYXRvZ3JhcGh5KSIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMSAwOToyOTo1NSBDRVQiDQogICAgfSwNCiAgICAiMTkwNiI6IHsNCiAgICAgICJkaXNwbGF5IjogIkF6dXJlIEJpb3RlY2ggSW5jLCBDT1ZJRC0xOSBBbnRpZ2VuIFJhcGlkIFRlc3QgRGV2aWNlIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTE5IDE3OjE0OjIxIENFVCINCiAgICB9LA0KICAgICIxODcwIjogew0KICAgICAgImRpc3BsYXkiOiAiQmVpamluZyBIb3RnZW4gQmlvdGVjaCBDby4sIEx0ZCwgTm92ZWwgQ29yb25hdmlydXMgMjAxOS1uQ29WIEFudGlnZW4gVGVzdCAoQ29sbG9pZGFsIEdvbGQpIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDIwOjA3OjMwIENFVCINCiAgICB9LA0KICAgICIxMzMxIjogew0KICAgICAgImRpc3BsYXkiOiAiQmVpamluZyBMZXB1IE1lZGljYWwgVGVjaG5vbG9neSBDby4sIEx0ZCwgU0FSUy1Db1YtMiBBbnRpZ2VuIFJhcGlkIFRlc3QgS2l0IiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDEzOjA0OjAwIENFVCINCiAgICB9LA0KICAgICIxNDg0Ijogew0KICAgICAgImRpc3BsYXkiOiAiQmVpamluZyBXYW50YWkgQmlvbG9naWNhbCBQaGFybWFjeSBFbnRlcnByaXNlIENvLiwgTHRkLCBXYW50YWkgU0FSUy1Db1YtMiBBZyBSYXBpZCBUZXN0IChGSUEpIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDEzOjA0OjAwIENFVCINCiAgICB9LA0KICAgICIxMjIzIjogew0KICAgICAgImRpc3BsYXkiOiAiQklPU1lORVggUy5BLiwgQklPU1lORVggQ09WSUQtMTkgQWcgQlNTIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDEzOjE4OjIwIENFVCINCiAgICB9LA0KICAgICIxMjM2Ijogew0KICAgICAgImRpc3BsYXkiOiAiQlROWCBJbmMsIFJhcGlkIFJlc3BvbnNlIENPVklELTE5IEFudGlnZW4gUmFwaWQgVGVzdCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxOTo0MDoxMyBDRVQiDQogICAgfSwNCiAgICAiMTE3MyI6IHsNCiAgICAgICJkaXNwbGF5IjogIkNlclRlc3QgQmlvdGVjLCBDZXJUZXN0IFNBUlMtQ29WLTIgQ2FyZCB0ZXN0IiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDEzOjE4OjIwIENFVCINCiAgICB9LA0KICAgICIxOTE5Ijogew0KICAgICAgImRpc3BsYXkiOiAiQ29yZSBUZWNobm9sb2d5IENvLiwgTHRkLCBDb3JldGVzdHMgQ09WSUQtMTkgQWcgVGVzdCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAyMDoxMjo1MSBDRVQiDQogICAgfSwNCiAgICAiMTIyNSI6IHsNCiAgICAgICJkaXNwbGF5IjogIkREUyBESUFHTk9TVElDLCBUZXN0IFJhcGlkIENvdmlkLTE5IEFudGlnZW4gKHRhbXBvbiBuYXpvZmFyaW5naWFuKSIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxOTo0MDoxMyBDRVQiDQogICAgfSwNCiAgICAiMTM3NSI6IHsNCiAgICAgICJkaXNwbGF5IjogIkRJQUxBQiBHbWJILCBESUFRVUlDSyBDT1ZJRC0xOSBBZyBDYXNzZXR0ZSIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAyMDowNzozMCBDRVQiDQogICAgfSwNCiAgICAiMTI0NCI6IHsNCiAgICAgICJkaXNwbGF5IjogIkdlbkJvZHksIEluYywgR2VuYm9keSBDT1ZJRC0xOSBBZyBUZXN0IiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDEzOjA0OjAwIENFVCINCiAgICB9LA0KICAgICIxMjUzIjogew0KICAgICAgImRpc3BsYXkiOiAiR2VuU3VyZSBCaW90ZWNoIEluYywgR2VuU3VyZSBDT1ZJRC0xOSBBbnRpZ2VuIFJhcGlkIEtpdCAoUkVGOiBQMjAwNCkiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTk6NDA6MTQgQ0VUIg0KICAgIH0sDQogICAgIjExNDQiOiB7DQogICAgICAiZGlzcGxheSI6ICJHcmVlbiBDcm9zcyBNZWRpY2FsIFNjaWVuY2UgQ29ycC4sIEdFTkVESUEgVyBDT1ZJRC0xOSBBZyIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMSAwOTozMTowOSBDRVQiDQogICAgfSwNCiAgICAiMTc0NyI6IHsNCiAgICAgICJkaXNwbGF5IjogIkd1YW5nZG9uZyBIZWNpbiBTY2llbnRpZmljLCBJbmMuLCAyMDE5LW5Db1YgQW50aWdlbiBUZXN0IEtpdCAoY29sbG9pZGFsIGdvbGQgbWV0aG9kKSIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxOTo0MDoxNCBDRVQiDQogICAgfSwNCiAgICAiMTM2MCI6IHsNCiAgICAgICJkaXNwbGF5IjogIkd1YW5nZG9uZyBXZXNhaWwgQmlvdGVjaCBDby4sIEx0ZCwgQ09WSUQtMTkgQWcgVGVzdCBLaXQiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTM6MDQ6MDAgQ0VUIg0KICAgIH0sDQogICAgIjE0MzciOiB7DQogICAgICAiZGlzcGxheSI6ICJHdWFuZ3pob3UgV29uZGZvIEJpb3RlY2ggQ28uLCBMdGQsIFdvbmRmbyAyMDE5LW5Db1YgQW50aWdlbiBUZXN0IChMYXRlcmFsIEZsb3cgTWV0aG9kKSIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAyMDowNzozMCBDRVQiDQogICAgfSwNCiAgICAiMTI1NiI6IHsNCiAgICAgICJkaXNwbGF5IjogIkhhbmd6aG91IEFsbFRlc3QgQmlvdGVjaCBDby4sIEx0ZCwgQ09WSUQtMTkgYW5kIEluZmx1ZW56YSBBK0IgQW50aWdlbiBDb21ibyBSYXBpZCBUZXN0IiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDE5OjQwOjE0IENFVCINCiAgICB9LA0KICAgICIxMzYzIjogew0KICAgICAgImRpc3BsYXkiOiAiSGFuZ3pob3UgQ2xvbmdlbmUgQmlvdGVjaCBDby4sIEx0ZCwgQ292aWQtMTkgQW50aWdlbiBSYXBpZCBUZXN0IEtpdCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxMzowNDowMCBDRVQiDQogICAgfSwNCiAgICAiMTM2NSI6IHsNCiAgICAgICJkaXNwbGF5IjogIkhhbmd6aG91IENsb25nZW5lIEJpb3RlY2ggQ28uLCBMdGQsIENPVklELTE5L0luZmx1ZW56YSBBK0IgQW50aWdlbiBDb21ibyBSYXBpZCBUZXN0IiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDE5OjQwOjE0IENFVCINCiAgICB9LA0KICAgICIxODQ0Ijogew0KICAgICAgImRpc3BsYXkiOiAiSGFuZ3pob3UgSW1tdW5vIEJpb3RlY2ggQ28uLEx0ZCwgSW1tdW5vYmlvIFNBUlMtQ29WLTIgQW50aWdlbiBBTlRFUklPUiBOQVNBTCBSYXBpZCBUZXN0IEtpdCAobWluaW1hbCBpbnZhc2l2ZSkiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTk6NDA6MTQgQ0VUIg0KICAgIH0sDQogICAgIjEyMTUiOiB7DQogICAgICAiZGlzcGxheSI6ICJIYW5nemhvdSBMYWloZSBCaW90ZWNoIENvLiwgTHRkLCBMWUhFUiBOb3ZlbCBDb3JvbmF2aXJ1cyAoQ09WSUQtMTkpIEFudGlnZW4gVGVzdCBLaXQoQ29sbG9pZGFsIEdvbGQpIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDE5OjQwOjEzIENFVCINCiAgICB9LA0KICAgICIxMzkyIjogew0KICAgICAgImRpc3BsYXkiOiAiSGFuZ3pob3UgVGVzdHNlYSBCaW90ZWNobm9sb2d5IENvLiwgTHRkLCBDT1ZJRC0xOSBBbnRpZ2VuIFRlc3QgQ2Fzc2V0dGUiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTk6NDA6MTQgQ0VUIg0KICAgIH0sDQogICAgIjE3NjciOiB7DQogICAgICAiZGlzcGxheSI6ICJIZWFsZ2VuIFNjaWVudGlmaWMsIENvcm9uYXZpcnVzIEFnIFJhcGlkIFRlc3QgQ2Fzc2V0dGUiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTM6MTg6MjAgQ0VUIg0KICAgIH0sDQogICAgIjEyNjMiOiB7DQogICAgICAiZGlzcGxheSI6ICJIdW1hc2lzLCBIdW1hc2lzIENPVklELTE5IEFnIFRlc3QiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMjA6MDc6MzAgQ0VUIg0KICAgIH0sDQogICAgIjEzMzMiOiB7DQogICAgICAiZGlzcGxheSI6ICJKb2luc3RhciBCaW9tZWRpY2FsIFRlY2hub2xvZ3kgQ28uLCBMdGQsIENPVklELTE5IFJhcGlkIEFudGlnZW4gVGVzdCAoQ29sbG9pZGFsIEdvbGQpIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDIwOjA3OjMwIENFVCINCiAgICB9LA0KICAgICIxNzY0Ijogew0KICAgICAgImRpc3BsYXkiOiAiSk9ZU0JJTyAoVGlhbmppbikgQmlvdGVjaG5vbG9neSBDby4sIEx0ZCwgU0FSUy1Db1YtMiBBbnRpZ2VuIFJhcGlkIFRlc3QgS2l0IChDb2xsb2lkYWwgR29sZCkiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTEgMDk6Mjg6MTAgQ0VUIg0KICAgIH0sDQogICAgIjEyNjYiOiB7DQogICAgICAiZGlzcGxheSI6ICJMYWJub3ZhdGlvbiBUZWNobm9sb2dpZXMgSW5jLCBTQVJTLUNvVi0yIEFudGlnZW4gUmFwaWQgVGVzdCBLaXQiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTk6NDA6MTQgQ0VUIg0KICAgIH0sDQogICAgIjEyNjciOiB7DQogICAgICAiZGlzcGxheSI6ICJMdW1pUXVpY2sgRGlhZ25vc3RpY3MgSW5jLCBRdWlja1Byb2ZpbGUgQ09WSUQtMTkgQW50aWdlbiBUZXN0IiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDIwOjA3OjMwIENFVCINCiAgICB9LA0KICAgICIxMjY4Ijogew0KICAgICAgImRpc3BsYXkiOiAiTHVtaXJhRFgsIEx1bWlyYUR4IFNBUlMtQ29WLTIgQWcgVGVzdCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxMzoxODoyMCBDRVQiDQogICAgfSwNCiAgICAiMTE4MCI6IHsNCiAgICAgICJkaXNwbGF5IjogIk1FRHNhbiBHbWJILCBNRURzYW4gU0FSUy1Db1YtMiBBbnRpZ2VuIFJhcGlkIFRlc3QiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMjA6MDc6MzAgQ0VUIg0KICAgIH0sDQogICAgIjExOTAiOiB7DQogICAgICAiZGlzcGxheSI6ICJtw7ZMYWIsIENPVklELTE5IFJhcGlkIEFudGlnZW4gVGVzdCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxOTo0MDoxMyBDRVQiDQogICAgfSwNCiAgICAiMTQ4MSI6IHsNCiAgICAgICJkaXNwbGF5IjogIk1QIEJpb21lZGljYWxzLCBSYXBpZCBTQVJTLUNvVi0yIEFudGlnZW4gVGVzdCBDYXJkIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDIwOjA3OjMwIENFVCINCiAgICB9LA0KICAgICIxMTYyIjogew0KICAgICAgImRpc3BsYXkiOiAiTmFsIHZvbiBtaW5kZW4gR21iSCwgTkFEQUwgQ09WSUQtMTkgQWcgVGVzdCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxMzowNDowMCBDRVQiDQogICAgfSwNCiAgICAiMTQyMCI6IHsNCiAgICAgICJkaXNwbGF5IjogIk5hbm9FbnRlaywgRlJFTkQgQ09WSUQtMTkgQWciLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTk6NDA6MTQgQ0VUIg0KICAgIH0sDQogICAgIjExOTkiOiB7DQogICAgICAiZGlzcGxheSI6ICJPbmNvc2VtIE9ua29sb2ppayBTaXN0ZW1sZXIgU2FuLiB2ZSBUaWMuIEEuUy4sIENBVCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxOTo0MDoxMyBDRVQiDQogICAgfSwNCiAgICAiMzA4Ijogew0KICAgICAgImRpc3BsYXkiOiAiUENMIEluYywgUENMIENPVklEMTkgQWcgUmFwaWQgRklBIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDIwOjA3OjMwIENFVCINCiAgICB9LA0KICAgICIxMjcxIjogew0KICAgICAgImRpc3BsYXkiOiAiUHJlY2lzaW9uIEJpb3NlbnNvciwgSW5jLCBFeGRpYSBDT1ZJRC0xOSBBZyIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxMzowNDowMCBDRVQiDQogICAgfSwNCiAgICAiMTM0MSI6IHsNCiAgICAgICJkaXNwbGF5IjogIlFpbmdkYW8gSGlnaHRvcCBCaW90ZWNoIENvLiwgTHRkLCBTQVJTLUNvVi0yIEFudGlnZW4gUmFwaWQgVGVzdCAoSW1tdW5vY2hyb21hdG9ncmFwaHkpIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDEzOjA0OjAwIENFVCINCiAgICB9LA0KICAgICIxMDk3Ijogew0KICAgICAgImRpc3BsYXkiOiAiUXVpZGVsIENvcnBvcmF0aW9uLCBTb2ZpYSBTQVJTIEFudGlnZW4gRklBIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDEzOjA0OjAwIENFVCINCiAgICB9LA0KICAgICIxNjA2Ijogew0KICAgICAgImRpc3BsYXkiOiAiUmFwaUdFTiBJbmMsIEJJT0NSRURJVCBDT1ZJRC0xOSBBZyAtIFNBUlMtQ29WIDIgQW50aWdlbiB0ZXN0IiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDIwOjA3OjMwIENFVCINCiAgICB9LA0KICAgICIxNjA0Ijogew0KICAgICAgImRpc3BsYXkiOiAiUm9jaGUgKFNEIEJJT1NFTlNPUiksIFNBUlMtQ29WLTIgQW50aWdlbiBSYXBpZCBUZXN0IiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDIwOjA3OjMwIENFVCINCiAgICB9LA0KICAgICIxNDg5Ijogew0KICAgICAgImRpc3BsYXkiOiAiU2FmZWNhcmUgQmlvdGVjaCAoSGFuZ3pob3UpIENvLiBMdGQsIENPVklELTE5IEFudGlnZW4gUmFwaWQgVGVzdCBLaXQgKFN3YWIpIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEyIDEyOjU4OjI1IENFVCINCiAgICB9LA0KICAgICIxNDkwIjogew0KICAgICAgImRpc3BsYXkiOiAiU2FmZWNhcmUgQmlvdGVjaCAoSGFuZ3pob3UpIENvLiBMdGQsIE11bHRpLVJlc3BpcmF0b3J5IFZpcnVzIEFudGlnZW4gVGVzdCBLaXQoU3dhYikgIChJbmZsdWVuemEgQStCLyBDT1ZJRC0xOSkiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTk6NDA6MTQgQ0VUIg0KICAgIH0sDQogICAgIjM0NCI6IHsNCiAgICAgICJkaXNwbGF5IjogIlNEIEJJT1NFTlNPUiBJbmMsIFNUQU5EQVJEIEYgQ09WSUQtMTkgQWcgRklBIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDEzOjA0OjAwIENFVCINCiAgICB9LA0KICAgICIzNDUiOiB7DQogICAgICAiZGlzcGxheSI6ICJTRCBCSU9TRU5TT1IgSW5jLCBTVEFOREFSRCBRIENPVklELTE5IEFnIFRlc3QiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTM6MDQ6MDAgQ0VUIg0KICAgIH0sDQogICAgIjEzMTkiOiB7DQogICAgICAiZGlzcGxheSI6ICJTR0EgTWVkaWthbCwgVi1DaGVrIFNBUlMtQ29WLTIgQWcgUmFwaWQgVGVzdCBLaXQgKENvbGxvaWRhbCBHb2xkKSIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxOTo0MDoxNCBDRVQiDQogICAgfSwNCiAgICAiMjAxNyI6IHsNCiAgICAgICJkaXNwbGF5IjogIlNoZW56aGVuIFVsdHJhLURpYWdub3N0aWNzIEJpb3RlYy5Dby4sTHRkLCBTQVJTLUNvVi0yIEFudGlnZW4gVGVzdCBLaXQiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTkgMTc6MTU6MzggQ0VUIg0KICAgIH0sDQogICAgIjE3NjkiOiB7DQogICAgICAiZGlzcGxheSI6ICJTaGVuemhlbiBXYXRtaW5kIE1lZGljYWwgQ28uLCBMdGQsIFNBUlMtQ29WLTIgQWcgRGlhZ25vc3RpYyBUZXN0IEtpdCAoQ29sbG9pZGFsIEdvbGQpIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDIwOjA3OjMwIENFVCINCiAgICB9LA0KICAgICIxNTc0Ijogew0KICAgICAgImRpc3BsYXkiOiAiU2hlbnpoZW4gWmhlbnJ1aSBCaW90ZWNobm9sb2d5IENvLiwgTHRkLCBaaGVucnVpIMKuQ09WSUQtMTkgQW50aWdlbiBUZXN0IENhc3NldHRlIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDE5OjQwOjE0IENFVCINCiAgICB9LA0KICAgICIxMjE4Ijogew0KICAgICAgImRpc3BsYXkiOiAiU2llbWVucyBIZWFsdGhpbmVlcnMsIENMSU5JVEVTVCBSYXBpZCBDb3ZpZC0xOSBBbnRpZ2VuIFRlc3QiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTM6MDQ6MDAgQ0VUIg0KICAgIH0sDQogICAgIjExMTQiOiB7DQogICAgICAiZGlzcGxheSI6ICJTdWdlbnRlY2gsIEluYywgU0dUaS1mbGV4IENPVklELTE5IEFnIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTEwIDE5OjQwOjEzIENFVCINCiAgICB9LA0KICAgICIxNDY2Ijogew0KICAgICAgImRpc3BsYXkiOiAiVE9EQSBQSEFSTUEsIFRPREEgQ09ST05BRElBRyBBZyIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAyMDowNzozMCBDRVQiDQogICAgfSwNCiAgICAiMTkzNCI6IHsNCiAgICAgICJkaXNwbGF5IjogIlRvZHkgTGFib3JhdG9yaWVzIEludC4sIENvcm9uYXZpcnVzIChTQVJTLUNvViAyKSBBbnRpZ2VuIC0gT3JhbCBGbHVpZCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xOSAxNzoxNjo0MiBDRVQiDQogICAgfSwNCiAgICAiMTQ0MyI6IHsNCiAgICAgICJkaXNwbGF5IjogIlZpdHJvc2VucyBCaW90ZWNobm9sb2d5IENvLiwgTHRkLCBSYXBpZEZvciBTQVJTLUNvVi0yIFJhcGlkIEFnIFRlc3QiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTk6NDA6MTQgQ0VUIg0KICAgIH0sDQogICAgIjEyNDYiOiB7DQogICAgICAiZGlzcGxheSI6ICJWaXZhQ2hlayBCaW90ZWNoIChIYW5nemhvdSkgQ28uLCBMdGQsIFZpdmFkaWFnIFNBUlMgQ29WIDIgQWcgUmFwaWQgVGVzdCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxOTo0MDoxNCBDRVQiDQogICAgfSwNCiAgICAiMTc2MyI6IHsNCiAgICAgICJkaXNwbGF5IjogIlhpYW1lbiBBbW9uTWVkIEJpb3RlY2hub2xvZ3kgQ28uLCBMdGQsIENPVklELTE5IEFudGlnZW4gUmFwaWQgVGVzdCBLaXQgKENvbGxvaWRhbCBHb2xkKSIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxOTo0MDoxNCBDRVQiDQogICAgfSwNCiAgICAiMTI3OCI6IHsNCiAgICAgICJkaXNwbGF5IjogIlhpYW1lbiBCb3NvbiBCaW90ZWNoIENvLiBMdGQsIFJhcGlkIFNBUlMtQ29WLTIgQW50aWdlbiBUZXN0IENhcmQiLA0KICAgICAgImxhbmciOiAiZW4iLA0KICAgICAgImFjdGl2ZSI6IHRydWUsDQogICAgICAic3lzdGVtIjogImh0dHBzOi8vY292aWQtMTktZGlhZ25vc3RpY3MuanJjLmVjLmV1cm9wYS5ldS9kZXZpY2VzIiwNCiAgICAgICJ2ZXJzaW9uIjogIjIwMjEtMDUtMTAgMTM6MDQ6MDAgQ0VUIg0KICAgIH0sDQogICAgIjE0NTYiOiB7DQogICAgICAiZGlzcGxheSI6ICJYaWFtZW4gV2l6IEJpb3RlY2ggQ28uLCBMdGQsIFNBUlMtQ29WLTIgQW50aWdlbiBSYXBpZCBUZXN0IiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTE5IDE3OjEwOjIxIENFVCINCiAgICB9LA0KICAgICIxODg0Ijogew0KICAgICAgImRpc3BsYXkiOiAiWGlhbWVuIFdpeiBCaW90ZWNoIENvLiwgTHRkLCBTQVJTLUNvVi0yIEFudGlnZW4gUmFwaWQgVGVzdCAoQ29sbG9pZGFsIEdvbGQpIiwNCiAgICAgICJsYW5nIjogImVuIiwNCiAgICAgICJhY3RpdmUiOiB0cnVlLA0KICAgICAgInN5c3RlbSI6ICJodHRwczovL2NvdmlkLTE5LWRpYWdub3N0aWNzLmpyYy5lYy5ldXJvcGEuZXUvZGV2aWNlcyIsDQogICAgICAidmVyc2lvbiI6ICIyMDIxLTA1LTIwIDE1OjE1OjI1IENFVCINCiAgICB9LA0KICAgICIxMjk2Ijogew0KICAgICAgImRpc3BsYXkiOiAiWmhlamlhbmcgQW5qaSBTYWlhbmZ1IEJpb3RlY2ggQ28uLCBMdGQsIEFuZEx1Y2t5IENPVklELTE5IEFudGlnZW4gUmFwaWQgVGVzdCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxOTo0MDoxNCBDRVQiDQogICAgfSwNCiAgICAiMTI5NSI6IHsNCiAgICAgICJkaXNwbGF5IjogIlpoZWppYW5nIEFuamkgU2FpYW5mdSBCaW90ZWNoIENvLiwgTHRkLCByZU9wZW5UZXN0IENPVklELTE5IEFudGlnZW4gUmFwaWQgVGVzdCIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxOTo0MDoxNCBDRVQiDQogICAgfSwNCiAgICAiMTM0MyI6IHsNCiAgICAgICJkaXNwbGF5IjogIlpoZXpoaWFuZyBPcmllbnQgR2VuZSBCaW90ZWNoIENvLiwgTHRkLCBDb3JvbmF2aXJ1cyBBZyBSYXBpZCBUZXN0IENhc3NldHRlIChTd2FiKSIsDQogICAgICAibGFuZyI6ICJlbiIsDQogICAgICAiYWN0aXZlIjogdHJ1ZSwNCiAgICAgICJzeXN0ZW0iOiAiaHR0cHM6Ly9jb3ZpZC0xOS1kaWFnbm9zdGljcy5qcmMuZWMuZXVyb3BhLmV1L2RldmljZXMiLA0KICAgICAgInZlcnNpb24iOiAiMjAyMS0wNS0xMCAxMzoxODoyMCBDRVQiDQogICAgfQ0KICB9DQp9"), StandardCharsets.UTF_8)
        );

        valuesetRepository.save(vs);

        ratValuesetUpdateService.update();
    }
}
