import { Entry } from "har-format";
import jsonschema = require("jsonschema");

export type Application = "debugger" | "schemaManager";

export interface IDebugger {
  events: Entry[];
  addRequests: (requests: Entry[]) => void;
}

export interface IPageRequests {
  page: string;
  entries: Entry[];
}

export interface IBeaconSummary {
  appId: string;
  collector: string;
  eventName: string;
  id: string;
  method: string;
  page: string;
  payload: Map<string, string>;
  time: string;
  validity: BeaconValidity;
}

export type BeaconValidity = "Valid" | "Unrecognised" | "Invalid";
export type BeaconDetail = [string, any, string];

export interface IBeaconDetails {
  appId: string;
  collector: string;
  data: BeaconDetail[];
  method: string;
  name: string;
  time: string;
}

export interface ICache {
  [igluUri: string]: jsonschema.Schema;
}

export interface ISchemaStatus {
  [igluUri: string]: string | null;
}

export interface IErrorMessageSet {
  [errorType: string]: string[];
}

export interface IToolbar {
  addRequests: (requests: Entry[]) => void;
  changeApp: (app: Application) => void;
  clearRequests: () => void;
  setModal: (modalName: string) => void;
}

export interface IRowSet {
  setName: string;
}

export interface ITimeline {
  isActive: (beacon: IBeaconSummary) => boolean;
  filter?: RegExp;
  requests: Entry[];
  setActive: (beacon: IBeaconSummary) => void;
}

export interface IBeacon {
  activeBeacon?: IBeaconSummary;
}

export interface IBadRowsSummary {
  addRequests: (requests: Entry[]) => void;
  modal?: string;
  setModal: (modalName?: string) => void;
}

export interface ITomcatImport {
  [fieldName: string]: string | { [header: string]: string };
}

interface IProtTextField {
  deprecated?: boolean;
  header?: "text";
  name: string;
  type: "text";
}

interface IProtBoolField {
  deprecated?: boolean;
  name: string;
  type: "bool";
}

interface IProtNumbField {
  deprecated?: boolean;
  name: string;
  type: "numb";
}

interface IProtDoubField {
  deprecated?: boolean;
  name: string;
  type: "doub";
}

interface IProtUuidField {
  cookie?: string;
  deprecated?: boolean;
  name: string;
  type: "uuid";
}

interface IProtJsonField {
  deprecated?: boolean;
  name: string;
  type: "json";
}

interface IProtBa64Field {
  deprecated?: boolean;
  name: string;
  then: "json";
  type: "ba64";
}

interface IProtEnumField {
  deprecated?: boolean;
  name: string;
  type: "enum";
  values: string[];
}

interface IProtEpocField {
  deprecated?: boolean;
  name: string;
  type: "epoc";
}

interface IProtEmapField {
  deprecated?: boolean;
  name: string;
  type: "emap";
  values: { [val: string]: string };
}

export type ProtocolField =
  | IProtBa64Field
  | IProtBoolField
  | IProtDoubField
  | IProtEmapField
  | IProtEnumField
  | IProtEpocField
  | IProtJsonField
  | IProtNumbField
  | IProtTextField
  | IProtUuidField;
