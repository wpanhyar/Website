using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Web;
using Website.Providers;

namespace Website.Models
{
    public static class ReadFile
    {
        public static string UpdateHtmlFile(string fileName, List<WordsToReplace> wordsToReplace)
        {
            string input = string.Empty;
            try
            {
                var directory = System.AppDomain.CurrentDomain.BaseDirectory + @"/Email Templates/";

                StreamReader reader = new StreamReader(directory + fileName);
                input = reader.ReadToEnd();
                foreach (var item in wordsToReplace)
                {
                    input = input.Replace(item.FileWord, item.Replacement);
                }
            }
            catch (Exception ex)
            {
                Log.LogException(ex);
            }
            return input;   
        }
    }

    public class WordsToReplace
    {
        public string FileWord { get; set; }
        public string Replacement { get; set; }
    }
}