$(document).ready(function() {
  $('#equipment-table').DataTable({
      ajax: {
          url: '/get_equipment',
          dataSrc: ''
      },
      columns: [
          { data: 'name' },
          { data: 'type' }
      ]
  });
});