using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using SQLite.Net;
using StartFinance.Models;
using Windows.UI.Popups;

// The Blank Page item template is documented at https://go.microsoft.com/fwlink/?LinkId=234238

namespace StartFinance.Views
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class AppointmentPage : Page
    {
        SQLiteConnection conn;  // adding an SQLite connection
        string path = Path.Combine(Windows.Storage.ApplicationData.Current.LocalFolder.Path, "Findata.sqlite");

        private void Page_Loaded(object sender, RoutedEventArgs e)
        {
            Results();
        }
        public AppointmentPage()
        {

            this.InitializeComponent();

            NavigationCacheMode = Windows.UI.Xaml.Navigation.NavigationCacheMode.Enabled;
            /// Initializing a database
            conn = new SQLite.Net.SQLiteConnection(new SQLite.Net.Platform.WinRT.SQLitePlatformWinRT(), path);
            // Creating table
            Results();
        }






        private void Results()
        {
            conn.CreateTable<Appointment>();
            var query1 = conn.Table<Appointment>();
            AppointmentList.ItemsSource = query1.ToList();
        }

       
        private async void AddAppointment_Click(object sender, RoutedEventArgs e)
        {
            string eventName1 = EventName.Text.ToString();
            string location1 = Location.Text.ToString();
            string eventDate1 = EventDate.Date.Value.ToString();
      
            string startTime1 = StartTime.SelectedTime.ToString();
            string endTime1 = EndTime.SelectedTime.ToString();
            try
            {
                if ((eventDate1 =="") || (location1 == "") || (eventName1 == ""))
                {
                    MessageDialog dialog = new MessageDialog("Opps...! Must enter: Event name, Location, Date");
                    await dialog.ShowAsync();
                }
                else
                {
                    conn.CreateTable<Appointment>();
                    conn.Insert(new Appointment
                    {
                        EventName = eventName1,
                        Location = location1,
                        EventDate = eventDate1,
                        StartTime = startTime1,
                        EndTime = endTime1
                    }) ;
                    Results();
                }

            }
            catch (Exception ex)
            {
                if (ex is FormatException)
                {
                    MessageDialog dialog = new MessageDialog("There is a wrong format in data", "Oops..!");
                    await dialog.ShowAsync();
                }   // Exception handling when SQLite contraints are violated
                else if (ex is SQLiteException)
                {
                    MessageDialog dialog = new MessageDialog("Data already exist, Check record");
                    await dialog.ShowAsync();
                }
                else
                {
                    MessageDialog dialog = new MessageDialog("Something went wrong.");
                    await dialog.ShowAsync();
                }
            }
        }

        private async void DeleteAppointment_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                int AccSelection = ((Appointment)AppointmentList.SelectedItem).AppointmentId;
          
                if (AccSelection == 0)
                {
                    MessageDialog dialog = new MessageDialog("Not selected the Item", "Oops..!");
                    await dialog.ShowAsync();
                }
                else
                {
                    conn.CreateTable<Appointment>();
                    var query1 = conn.Table<Appointment>();
                    var query3 = conn.Query<Appointment>("DELETE FROM Appointment WHERE AppointmentId ='" + AccSelection + "'");
                    AppointmentList.ItemsSource = query1.ToList();
                }
                conn.CreateTable<Appointment>();
                var query = conn.Table<Appointment>();
                AppointmentList.ItemsSource = query.ToList();
            }
            catch (NullReferenceException)
            {
                MessageDialog dialog = new MessageDialog("Not selected the Item", "Oops..!");
                await dialog.ShowAsync();
            }

            
        }

        private async void EditAppointment_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string eventName1 = EventName.Text.ToString();
                string location1 = Location.Text.ToString();
                string eventDate1 = EventDate.Date.Value.ToString();
                string startTime1 = StartTime.SelectedTime.ToString();
                string endTime1 = EndTime.SelectedTime.ToString();

                int AppSelection = ((Appointment)AppointmentList.SelectedItem).AppointmentId;
               
                if (AppSelection == 0)
                {
                    MessageDialog dialog = new MessageDialog("Not selected the Item", "Oops..!");
                    await dialog.ShowAsync();
                }
                else
                {
                    var updateQuerry = conn.Query<Appointment>("UPDATE Appointment SET " +
                        "EventName = '" + eventName1 + "'," +
                        "Location = '" + location1 + "'," +
                        "EventDate = '" + eventDate1 + "'," +
                        "StartTime = '" + startTime1 + "',"+
                        "EndTime = '" + endTime1 + "'"+
                        "WHERE AppointmentId = '" + AppSelection + "';").FirstOrDefault();

                    conn.Update(updateQuerry);
                    Results();

                }

            }
            catch (NullReferenceException)
            {
                MessageDialog dialog = new MessageDialog("Not selected the Item", "Oops..!");
                await dialog.ShowAsync();
            }


        }

        private async void ClearAppointment_Click(object sender, RoutedEventArgs e)
        {
            EventName.Text = "";
            Location.Text = "";
            EventDate.Date = null;
            StartTime.SelectedTime = null;
            EndTime.SelectedTime= null;

            

            


        }


    }
}
