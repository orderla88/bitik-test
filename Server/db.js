import { Firestore } from "@google-cloud/firestore";

export const db = new Firestore({
  projectId: process.env.GCLOUD_PROJECT, // set in Cloud Run console
});
