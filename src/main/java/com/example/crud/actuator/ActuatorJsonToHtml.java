package com.example.crud.actuator;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class ActuatorJsonToHtml {

    public static String getHtmlData(String strJsonData) {
        try {
            JSONObject obj = new JSONObject(strJsonData);
            return jsonToHtml(obj);
        } catch (JSONException e) {
            return strJsonData;
        }
    }

    // static int inputLevel = 0;
    private static String jsonToHtml(Object obj) {
        StringBuilder html = new StringBuilder();

        try {
            if (obj instanceof JSONObject) {
                JSONObject jsonObject = (JSONObject) obj;
                String[] keys = JSONObject.getNames(jsonObject);

                html.append("<div style='margin-left:30px' class=\"json_object\">");

                if ((keys!=null) && (keys.length > 0)) {
                    for (String key : keys) {

                        // print the key and open a DIV
                        html.append("<div><span class=\"json_key\">")
                                .append(key).append("</span> : ");

                        Object val = jsonObject.get(key);

                        // recursive call
                        if (key.equals("href")) {
                            String subject = val.toString();
                            subject = subject.substring(subject.indexOf("actuator")+8);
                            if (subject.startsWith("/")) {
                                subject = subject.substring(1);
                            }
                            html.append("<a href=").append("http://localhost/api/monitor?data=" + subject).append(">").append(subject).append("</a>")
                                    .append(" <a href=").append("http://localhost/actuator/").append(subject).append(">").append("(orig)").append("</a>");
                        } else {
                            html.append(jsonToHtml(val));
                        }

                        // close the div
                        html.append("</div>");
                    }
                }

                html.append("</div>");

            } else if (obj instanceof JSONArray) {
                JSONArray array = (JSONArray) obj;
                for (int i = 0; i < array.length(); i++) {
                    // recursive call
                    html.append(jsonToHtml(array.get(i))).append(", ");
                }
            } else {
                // print the value
                html.append(obj);
            }
        } catch (JSONException e) {
            return e.getLocalizedMessage();
        }

        return html.toString();
    }
}