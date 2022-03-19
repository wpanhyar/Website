using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web;

namespace Website.Providers
{
    public static class Log
    {
        public static void LogString(string msg)
        {
            try
            {
                StreamWriter sw = new StreamWriter(GetPathAndFilename($"LogString-{DateTime.Now.ToString("ddmmyyyy")}.txt"), true);
                //Write a line of text
                sw.WriteLine(msg);
                //Close the file
                sw.Close();
            }
            catch { }
        }

        public static void LogException(Exception ex)
        {
            try
            {
                StreamWriter sw = new StreamWriter(GetPathAndFilename($"LogException-{DateTime.Now.ToString("ddmmyyyy")}.txt"), true);
                //Write a line of text
                sw.WriteLine(ex);
                //Close the file
                sw.Close();
            }
            catch { }
        }

        private static string GetPathAndFilename(string filename)
        {
            var currentDirectory = System.AppDomain.CurrentDomain.BaseDirectory + "\\Logs\\" + filename;
            if (!Directory.Exists(currentDirectory))
                Directory.CreateDirectory(currentDirectory);
            return currentDirectory ;
        }
    }
}